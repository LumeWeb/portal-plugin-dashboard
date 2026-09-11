package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/queryutil"
)

const API_KEY_SERVICE = "api_key"

// IssuedAPIKey is the result of issuing or reissuing an API key. ID is the
// persistent API key row; Token is the one-time JWT the caller hands to the
// runtime and then discards.
type IssuedAPIKey struct {
	ID        uint
	Token     string
	ExpiresAt time.Time
	UUID      uuid.UUID
	Name      string
}

type APIKeyService interface {
	core.Service
	CreateAPIKey(ctx context.Context, userID uint, name string) (*models.APIKey, error)
	// IssueAPIKey creates a new API key and returns the one-time signed token.
	// The JWT is not persisted; only the row ID and expiry are.
	IssueAPIKey(ctx context.Context, userID uint, name string, ttl time.Duration) (*IssuedAPIKey, error)
	// ReissueAPIKey refreshes the JWT for an existing key owned by the user,
	// used by workspace reconciliation after a restart or before expiry.
	ReissueAPIKey(ctx context.Context, userID uint, keyID uint, ttl time.Duration) (*IssuedAPIKey, error)
	// RevokeAPIKey deletes a key owned by the user by numeric row ID.
	RevokeAPIKey(ctx context.Context, userID uint, keyID uint) error
	GetAPIKeys(ctx context.Context, userID uint, filters []queryutil.CrudFilter, sorts []queryutil.Sort, pagination queryutil.Pagination) ([]*models.APIKey, int64, error)
	DeleteAPIKey(ctx context.Context, userID uint, uuid uuid.UUID) error
	ValidateAPIKey(ctx context.Context, userID uint, keyUUID uuid.UUID) (*models.APIKey, error)
	// RecordAPIKeyUsage stamps the key's last-used timestamp. It is invoked by
	// the auth middleware key logger (see NewAPIKeyUsageLogger) whenever a
	// purpose-"api" token is consumed, so it runs on the request hot path.
	RecordAPIKeyUsage(ctx context.Context, userID uint, keyUUID uuid.UUID) error
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
