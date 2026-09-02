// Package social_provider provides the SocialProviderService, the only owner of
// SocialProviderConfig database access. API handlers resolve provider configs
// through this service instead of querying the database directly.
package social_provider

import (
	"context"

	pluginCore "go.lumeweb.com/portal-plugin-dashboard/core"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/portal/db"
	"go.lumeweb.com/queryutil"
	"gorm.io/gorm"
)

// SocialProviderServiceDefault implements SocialProviderService.
type SocialProviderServiceDefault struct {
	*core.BaseComponent
}

// NewSocialProviderService creates the service.
func NewSocialProviderService() (core.Service, []core.ContextBuilderOption, error) {
	return &SocialProviderServiceDefault{}, nil, nil
}

func (s *SocialProviderServiceDefault) ID() string {
	return pluginCore.SOCIAL_PROVIDER_SERVICE
}

func (s *SocialProviderServiceDefault) List(ctx context.Context, filters []queryutil.CrudFilter, sorts []queryutil.Sort, pagination queryutil.Pagination) ([]*pluginDb.SocialProviderConfig, int64, error) {
	query := s.DB().WithContext(ctx).Model(&pluginDb.SocialProviderConfig{})
	query = queryutil.ApplyFilters(query, filters, nil)
	query = queryutil.ApplySort(query, sorts)

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	query = queryutil.ApplyPagination(query, pagination)
	var configs []*pluginDb.SocialProviderConfig
	if err := query.Find(&configs).Error; err != nil {
		return nil, 0, err
	}

	return configs, total, nil
}

func (s *SocialProviderServiceDefault) ListEnabled(ctx context.Context) ([]*pluginDb.SocialProviderConfig, error) {
	var configs []*pluginDb.SocialProviderConfig
	err := s.DB().WithContext(ctx).
		Where("enabled = ?", true).
		Order("order_index ASC, display_name ASC").
		Find(&configs).Error
	return configs, err
}

func (s *SocialProviderServiceDefault) Get(ctx context.Context, id uint) (*pluginDb.SocialProviderConfig, error) {
	var config pluginDb.SocialProviderConfig
	err := db.RetryableComponentTransaction(s, ctx, func(tx *gorm.DB) *gorm.DB {
		return tx.First(&config, id)
	})
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func (s *SocialProviderServiceDefault) Create(ctx context.Context, cfg *pluginDb.SocialProviderConfig) error {
	return db.RetryableComponentTransaction(s, ctx, func(tx *gorm.DB) *gorm.DB {
		return tx.Create(cfg)
	})
}

func (s *SocialProviderServiceDefault) Update(ctx context.Context, cfg *pluginDb.SocialProviderConfig) error {
	return db.RetryableComponentTransaction(s, ctx, func(tx *gorm.DB) *gorm.DB {
		return tx.Save(cfg)
	})
}

// Delete hard-deletes the provider config so its provider_id unique slot is
// freed for re-creation. It returns the number of deleted rows.
func (s *SocialProviderServiceDefault) Delete(ctx context.Context, id uint) (int64, error) {
	var rows int64
	err := db.RetryableComponentTransaction(s, ctx, func(tx *gorm.DB) *gorm.DB {
		res := tx.Unscoped().Delete(&pluginDb.SocialProviderConfig{}, id)
		rows = res.RowsAffected
		return res
	})
	return rows, err
}
