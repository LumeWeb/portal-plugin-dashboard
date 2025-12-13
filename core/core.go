package service

import (
	"github.com/google/uuid"
	"go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/queryutil"
)

const API_KEY_SERVICE = "api_key"

type APIKeyService interface {
	core.Service
	CreateAPIKey(userID uint, name string) (*models.APIKey, error)
	GetAPIKeys(userID uint, filters []queryutil.CrudFilter, sorts []queryutil.Sort, pagination queryutil.Pagination) ([]*models.APIKey, int64, error)
	DeleteAPIKey(userID uint, uuid uuid.UUID) error
	ValidateAPIKey(userID uint, keyUUID uuid.UUID) (*models.APIKey, error)
}
