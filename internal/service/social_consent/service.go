// Package social_consent claims one-time link approvals in durable storage.
package social_consent

import (
	"context"
	"errors"
	"time"

	pluginCore "go.lumeweb.com/portal-plugin-dashboard/core"
	"go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/portal/db"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var _ pluginCore.SocialConsentService = (*SocialConsentServiceDefault)(nil)

type SocialConsentServiceDefault struct {
	*core.BaseComponent
}

func NewSocialConsentService() (core.Service, []core.ContextBuilderOption, error) {
	return &SocialConsentServiceDefault{}, nil, nil
}

func (s *SocialConsentServiceDefault) ID() string {
	return pluginCore.SOCIAL_CONSENT_SERVICE
}

// Consume claims a signed consent nonce once, even across portal instances.
func (s *SocialConsentServiceDefault) Consume(ctx context.Context, token string, expiresAt time.Time) error {
	if token == "" || !expiresAt.After(time.Now()) {
		return pluginCore.ErrInvalidConsent
	}
	if s.DB() == nil {
		return errors.New("consent database unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Cleanup is separate from the claim transaction: a read-before-write
	// transaction cannot upgrade its SQLite snapshot when another instance wins.
	var expired []string
	if err := s.DB().WithContext(ctx).Model(&models.SocialConsent{}).Where("expires_at <= ?", time.Now()).Limit(100).Pluck("token", &expired).Error; err != nil {
		return err
	}
	if len(expired) > 0 {
		if err := s.DB().WithContext(ctx).Where("token IN ?", expired).Delete(&models.SocialConsent{}).Error; err != nil {
			return err
		}
	}

	var claimed bool
	err := db.RetryableComponentTransaction(s, ctx, func(tx *gorm.DB) *gorm.DB {
		result := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&models.SocialConsent{Token: token, ExpiresAt: expiresAt})
		claimed = result.RowsAffected == 1
		return result
	})
	if err != nil {
		return err
	}
	if !claimed {
		return pluginCore.ErrInvalidConsent
	}
	return nil
}
