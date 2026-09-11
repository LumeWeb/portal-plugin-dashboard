package api_key

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	pluginCore "go.lumeweb.com/portal-plugin-dashboard/core"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/portal/db"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// signAPIKeyJWT creates a purpose-"api" JWT for the given user and key. The
// JWT claims mirror the previous handler-side issuance: subject is the user
// ID string and ID is the key UUID.
func (s *APIKeyServiceDefault) signAPIKeyJWT(key *pluginDb.APIKey, ttl time.Duration) (string, time.Time, error) {
	configProvider := adapter.NewFromCore(s.Context())
	privateKey := configProvider.GetPrivateKey()
	domain := configProvider.GetDomain()

	expiresAt := time.Now().Add(ttl)
	token, err := jwt.CreateToken(
		privateKey,
		domain,
		fmt.Sprintf("%d", key.UserID),
		PurposeAPI,
		ttl,
		jwt.WithClaims(&jwt.RegisteredClaims{
			ID: key.UUID.String(),
		}),
	)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign API key jwt: %w", err)
	}
	return token, expiresAt, nil
}

// IssueAPIKey creates a new API key for the user, signs it, and returns the
// one-time token. The APIKey row is created and its expiry is persisted in the
// same transaction so a failure after the row is created cannot leave an
// orphaned row with a NULL Expires behind. The token is never persisted; only
// the row ID and expiry are stored. Keep the returned token only long enough
// to hand it to the runtime environment configured for the workspace.
func (s *APIKeyServiceDefault) IssueAPIKey(ctx context.Context, userID uint, name string, ttl time.Duration) (*pluginCore.IssuedAPIKey, error) {
	ctx, span := core.TraceMethod(ctx, "APIKeyServiceDefault.IssueAPIKey")
	defer span.End()

	var issued *pluginCore.IssuedAPIKey

	err := db.RetryableComponentTransaction(s, ctx, func(tx *gorm.DB) *gorm.DB {
		apiKey := &pluginDb.APIKey{
			Name:   name,
			UserID: userID,
		}
		if errTx := tx.Create(apiKey).Error; errTx != nil {
			return tx
		}

		token, expiresAt, errTx := s.signAPIKeyJWT(apiKey, ttl)
		if errTx != nil {
			_ = tx.AddError(errTx)
			return tx
		}

		// Persist the expiry in the same transaction as the row creation. If
		// this write fails the whole transaction rolls back, so no API-key row
		// is left behind.
		if errTx := tx.Model(&pluginDb.APIKey{}).Where("id = ?", apiKey.ID).Update("expires", expiresAt).Error; errTx != nil {
			_ = tx.AddError(errTx)
			return tx
		}

		apiKey.Expires = &expiresAt
		issued = &pluginCore.IssuedAPIKey{ID: apiKey.ID, Token: token, ExpiresAt: expiresAt, UUID: apiKey.UUID.ToUUID(), Name: apiKey.Name}
		return tx
	})
	if err != nil {
		s.Logger().Error("failed to issue api key", zap.Error(err))
		return nil, fmt.Errorf("failed to issue api key: %w", err)
	}

	return issued, nil
}

// ReissueAPIKey refreshes the JWT for an existing API key owned by the user,
// updating its expiry to ttl from now. Used by reconciliation after a portal
// restart or to rotate the runtime token before it expires.
func (s *APIKeyServiceDefault) ReissueAPIKey(ctx context.Context, userID uint, keyID uint, ttl time.Duration) (*pluginCore.IssuedAPIKey, error) {
	ctx, span := core.TraceMethod(ctx, "APIKeyServiceDefault.ReissueAPIKey")
	defer span.End()

	var key pluginDb.APIKey
	err := db.RetryableComponentTransaction(s, ctx, func(tx *gorm.DB) *gorm.DB {
		return tx.Where("id = ? AND user_id = ?", keyID, userID).First(&key)
	})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, gorm.ErrRecordNotFound
		}
		s.Logger().Error("failed to load api key for reissue", zap.Error(err))
		return nil, fmt.Errorf("failed to load api key for reissue: %w", err)
	}

	token, expiresAt, err := s.signAPIKeyJWT(&key, ttl)
	if err != nil {
		s.Logger().Error("failed to sign reissued api key", zap.Error(err))
		return nil, err
	}

	err = db.RetryableComponentTransaction(s, ctx, func(tx *gorm.DB) *gorm.DB {
		return tx.Model(&pluginDb.APIKey{}).Where("id = ?", key.ID).Update("expires", expiresAt)
	})
	if err != nil {
		s.Logger().Error("failed to update reissued api key expiry", zap.Error(err))
		return nil, fmt.Errorf("failed to update reissued api key expiry: %w", err)
	}

	return &pluginCore.IssuedAPIKey{ID: key.ID, Token: token, ExpiresAt: expiresAt, UUID: key.UUID.ToUUID(), Name: key.Name}, nil
}

// RevokeAPIKey soft-deletes an API key owned by the user by its numeric row ID.
// This is the revoke path for workspace-scoped keys, which the workspace
// service addresses by Workspace.APIKeyID.
func (s *APIKeyServiceDefault) RevokeAPIKey(ctx context.Context, userID uint, keyID uint) error {
	ctx, span := core.TraceMethod(ctx, "APIKeyServiceDefault.RevokeAPIKey")
	defer span.End()

	return core.MetricTrack(
		Duration.WithLabelValues(LabelOpDelete),
		Errors.WithLabelValues(LabelOpDelete),
		func() error {
			err := db.RetryableComponentTransaction(s, ctx, func(tx *gorm.DB) *gorm.DB {
				result := tx.Where("id = ? AND user_id = ?", keyID, userID).Delete(&pluginDb.APIKey{})
				if result.RowsAffected == 0 {
					_ = tx.AddError(gorm.ErrRecordNotFound)
				}
				return tx
			})
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				s.Logger().Error("failed to revoke api key", zap.Error(err))
				return fmt.Errorf("failed to revoke api key: %w", err)
			}
			// A missing key is already revoked; treat as success.
			return nil
		},
	)
}
