package service

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/portal/db"
	"go.lumeweb.com/portal/db/types"
	"go.lumeweb.com/queryutil"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"time"
)

const API_KEY_SERVICE = "api_key"

var (
	PurposeAPI jwt.Purpose = "api"
)

type APIKeyService interface {
	core.Service
	CreateAPIKey(userID uint, name string) (*pluginDb.APIKey, error)
	GetAPIKeys(userID uint, filters []queryutil.CrudFilter, sorts []queryutil.Sort, pagination queryutil.Pagination) ([]*pluginDb.APIKey, int64, error)
	DeleteAPIKey(userID uint, uuid uuid.UUID) error
	ValidateAPIKey(userID uint, keyUUID uuid.UUID) (*pluginDb.APIKey, error)
}

var _ APIKeyService = (*APIKeyServiceDefault)(nil)

type APIKeyServiceDefault struct {
	ctx    core.Context
	db     *gorm.DB
	logger *core.Logger
	user   core.UserService
	auth   core.AuthService
}

func NewAPIKeyService() (core.Service, []core.ContextBuilderOption, error) {
	service := &APIKeyServiceDefault{}

	return service, core.ContextOptions(
		core.ContextWithStartupFunc(func(ctx core.Context) error {
			service.ctx = ctx
			service.db = ctx.DB()
			service.logger = ctx.ServiceLogger(service)
			service.user = core.GetService[core.UserService](ctx, core.USER_SERVICE)
			service.auth = core.GetService[core.AuthService](ctx, core.AUTH_SERVICE)

			return service.db.AutoMigrate(&pluginDb.APIKey{})
		}),
	), nil
}

func (s *APIKeyServiceDefault) ID() string {
	return API_KEY_SERVICE
}

func (s *APIKeyServiceDefault) CreateAPIKey(userID uint, name string) (*pluginDb.APIKey, error) {
	apiKey := &pluginDb.APIKey{
		Name:   name,
		UserID: userID,
	}

	err := db.RetryableTransaction(s.ctx, s.db, func(tx *gorm.DB) *gorm.DB {
		return tx.Create(apiKey)
	})

	if err != nil {
		s.logger.Error("failed to create API key", zap.Error(err))
		return nil, fmt.Errorf("failed to create API key: %w", err)
	}

	return apiKey, nil
}

func (s *APIKeyServiceDefault) GetAPIKeys(userID uint, filters []queryutil.CrudFilter, sorts []queryutil.Sort, pagination queryutil.Pagination) ([]*pluginDb.APIKey, int64, error) {
	var apiKeys []*pluginDb.APIKey
	var total int64

	query := s.db.Model(&pluginDb.APIKey{}).Where(&pluginDb.APIKey{UserID: userID})

	// Apply filters, sorts and pagination using queryutil helpers
	query = queryutil.ApplyFilters(query, filters, nil)
	query = queryutil.ApplySort(query, sorts)

	if err := query.Count(&total).Error; err != nil {
		s.logger.Error("failed to count API keys", zap.Error(err))
		return nil, 0, fmt.Errorf("failed to count API keys: %w", err)
	}

	query = queryutil.ApplyPagination(query, pagination)

	if err := query.Find(&apiKeys).Error; err != nil {
		s.logger.Error("failed to fetch API keys", zap.Error(err))
		return nil, 0, fmt.Errorf("failed to fetch API keys: %w", err)
	}

	return apiKeys, total, nil
}

func (s *APIKeyServiceDefault) DeleteAPIKey(userID uint, keyID uuid.UUID) error {
	item := &pluginDb.APIKey{
		UserID: userID,
		UUID:   types.FromUUID(keyID),
	}

	err := db.RetryableTransaction(s.ctx, s.db, func(tx *gorm.DB) *gorm.DB {
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
		s.logger.Error("failed to delete API key", zap.Error(err))
		return fmt.Errorf("failed to delete API key: %w", err)
	}

	return nil
}

func (s *APIKeyServiceDefault) ValidateAPIKey(userID uint, keyUUID uuid.UUID) (*pluginDb.APIKey, error) {
	var apiKey pluginDb.APIKey

	if err := s.db.Where(&pluginDb.APIKey{UUID: types.FromUUID(keyUUID), UserID: userID}).First(&apiKey).Error; err != nil {
		return nil, fmt.Errorf("invalid api key")
	}

	// Check if key has expired
	if apiKey.Expires != nil && apiKey.Expires.Before(time.Now()) {
		return nil, fmt.Errorf("invalid api key")
	}

	return &apiKey, nil
}
