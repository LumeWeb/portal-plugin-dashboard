package service

import (
	"context"

	"github.com/google/uuid"
	"go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/queryutil"
)

const API_KEY_SERVICE = "api_key"

type APIKeyService interface {
	core.Service
	CreateAPIKey(ctx context.Context, userID uint, name string) (*models.APIKey, error)
	GetAPIKeys(ctx context.Context, userID uint, filters []queryutil.CrudFilter, sorts []queryutil.Sort, pagination queryutil.Pagination) ([]*models.APIKey, int64, error)
	DeleteAPIKey(ctx context.Context, userID uint, uuid uuid.UUID) error
	ValidateAPIKey(ctx context.Context, userID uint, keyUUID uuid.UUID) (*models.APIKey, error)
}

const SOCIAL_PROVIDER_SERVICE = "social_provider"

// SocialProviderService manages the DB-backed OAuth2 client provider configs.
// APIs route all provider config access through this service; handlers never
// touch the database directly.
type SocialProviderService interface {
	core.Service
	// List returns the provider configs matching the queryutil filters/sorts
	// with the matching total count.
	List(ctx context.Context, filters []queryutil.CrudFilter, sorts []queryutil.Sort, pagination queryutil.Pagination) ([]*models.SocialProviderConfig, int64, error)
	// ListEnabled returns the enabled provider configs for the public login
	// page, ordered by OrderIndex then DisplayName.
	ListEnabled(ctx context.Context) ([]*models.SocialProviderConfig, error)
	// Get returns the provider config by numeric id.
	Get(ctx context.Context, id uint) (*models.SocialProviderConfig, error)
	// Create inserts a provider config.
	Create(ctx context.Context, cfg *models.SocialProviderConfig) error
	// Update persists changes to an existing provider config.
	Update(ctx context.Context, cfg *models.SocialProviderConfig) error
	// Delete removes the provider config and its rows-affected count.
	Delete(ctx context.Context, id uint) (int64, error)
}
