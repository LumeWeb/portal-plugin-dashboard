package api_key

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	pluginCore "go.lumeweb.com/portal-plugin-dashboard/core"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/portal/db"
	"go.lumeweb.com/portal/db/types"
	"go.lumeweb.com/queryutil"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

var (
	PurposeAPI jwt.Purpose = "api"
)

type APIKeyServiceDefault struct {
	*core.BaseComponent
	user core.UserService
	auth core.AuthService
}

func NewAPIKeyService() (core.Service, []core.ContextBuilderOption, error) {
	svc := &APIKeyServiceDefault{}

	return svc, core.ContextOptions(
		core.ContextWithStartupFunc(func(ctx core.Context) error {
			svc.user = core.GetService[core.UserService](ctx, core.USER_SERVICE)
			svc.auth = core.GetService[core.AuthService](ctx, core.AUTH_SERVICE)

			return nil
		}),
	), nil
}

func (s *APIKeyServiceDefault) ID() string {
	return pluginCore.API_KEY_SERVICE
}

func (s *APIKeyServiceDefault) CreateAPIKey(ctx context.Context, userID uint, name string) (*pluginDb.APIKey, error) {
	ctx, span := core.TraceMethod(ctx, "APIKeyServiceDefault.CreateAPIKey")
	defer span.End()

	return core.MetricTrackResult(
		Duration.WithLabelValues(LabelOpCreate),
		nil,
		func() (*pluginDb.APIKey, error) {
			apiKey := &pluginDb.APIKey{
				Name:   name,
				UserID: userID,
			}

			err := db.RetryableComponentTransaction(s, ctx, func(tx *gorm.DB) *gorm.DB {
				return tx.Create(apiKey)
			})

			if err != nil {
				s.Logger().Error("failed to create API key", zap.Error(err))
				return nil, fmt.Errorf("failed to create API key: %w", err)
			}

			CreatedTotal.WithLabelValues().Inc()
			return apiKey, nil
		},
	)
}

func (s *APIKeyServiceDefault) GetAPIKeys(ctx context.Context, userID uint, filters []queryutil.CrudFilter, sorts []queryutil.Sort, pagination queryutil.Pagination) ([]*pluginDb.APIKey, int64, error) {
	ctx, span := core.TraceMethod(ctx, "APIKeyServiceDefault.GetAPIKeys")
	defer span.End()

	var apiKeys []*pluginDb.APIKey
	var total int64

	query := s.DB().Model(&pluginDb.APIKey{}).Where(&pluginDb.APIKey{UserID: userID})

	// Apply filters, sorts and pagination using queryutil helpers
	query = queryutil.ApplyFilters(query, filters, nil)
	query = queryutil.ApplySort(query, sorts)

	if err := query.Count(&total).Error; err != nil {
		s.Logger().Error("failed to count API keys", zap.Error(err))
		return nil, 0, fmt.Errorf("failed to count API keys: %w", err)
	}

	query = queryutil.ApplyPagination(query, pagination)

	if err := query.Find(&apiKeys).Error; err != nil {
		s.Logger().Error("failed to fetch API keys", zap.Error(err))
		return nil, 0, fmt.Errorf("failed to fetch API keys: %w", err)
	}

	return apiKeys, total, nil
}

func (s *APIKeyServiceDefault) DeleteAPIKey(ctx context.Context, userID uint, keyID uuid.UUID) error {
	ctx, span := core.TraceMethod(ctx, "APIKeyServiceDefault.DeleteAPIKey")
	defer span.End()

	return core.MetricTrack(
		Duration.WithLabelValues(LabelOpDelete),
		Errors.WithLabelValues(LabelOpDelete),
		func() error {
			item := &pluginDb.APIKey{
				UserID: userID,
				UUID:   types.FromUUID(keyID),
			}

			err := db.RetryableComponentTransaction(s, ctx, func(tx *gorm.DB) *gorm.DB {
				result := tx.Where(item).Delete(item)
				if result.Error != nil {
					return tx
				}
				if result.RowsAffected == 0 {
					_ = tx.AddError(gorm.ErrRecordNotFound)
					return tx
				}
				return tx
			})

			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return gorm.ErrRecordNotFound
				}
				s.Logger().Error("failed to delete API key", zap.Error(err))
				return fmt.Errorf("failed to delete API key: %w", err)
			}

			DeletedTotal.WithLabelValues().Inc()
			return nil
		},
	)
}

func (s *APIKeyServiceDefault) ValidateAPIKey(ctx context.Context, userID uint, keyUUID uuid.UUID) (*pluginDb.APIKey, error) {
	ctx, span := core.TraceMethod(ctx, "APIKeyServiceDefault.ValidateAPIKey")
	defer span.End()

	return core.MetricTrackResult(
		Duration.WithLabelValues(LabelOpValidate),
		Errors.WithLabelValues(LabelOpValidate),
		func() (*pluginDb.APIKey, error) {
			var apiKey pluginDb.APIKey

			err := db.RetryableComponentTransaction(s, ctx, func(tx *gorm.DB) *gorm.DB {
				return tx.Where(&pluginDb.APIKey{UUID: types.FromUUID(keyUUID), UserID: userID}).First(&apiKey)
			})

			if err != nil {
				return nil, fmt.Errorf("invalid api key")
			}

			// Check if key has expired (this is application logic, not DB operation)
			if apiKey.Expires != nil && apiKey.Expires.Before(time.Now()) {
				return nil, fmt.Errorf("invalid api key")
			}

			return &apiKey, nil
		},
	)
}
