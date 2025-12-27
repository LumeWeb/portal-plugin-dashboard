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
