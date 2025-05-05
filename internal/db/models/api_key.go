package models

import (
	"github.com/google/uuid"
	"go.lumeweb.com/portal/db/models"
	"time"

	"go.lumeweb.com/portal/db/types"
	"gorm.io/gorm"
)

type APIKey struct {
	gorm.Model
	Name    string           `gorm:"not null"`       // Descriptive name for the key
	UUID    types.BinaryUUID `gorm:"index;unique"`   // Unique identifier for the key
	UserID  uint             `gorm:"not null;index"` // Associated user ID
	User    models.User
	Expires *time.Time `gorm:"index"` // Optional expiration time (nil means never expires)
	JWT     string     `gorm:"-"`     // Transient field for generated JWT
}

// BeforeCreate generates UUID before creating record
func (k *APIKey) BeforeCreate(_ *gorm.DB) error {
	if k.UUID == types.FromUUID(uuid.Nil) {
		k.UUID = types.NewBinUUID()
	}
	return nil
}
