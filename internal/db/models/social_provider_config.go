package models

import (
	"encoding/json"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// SocialProviderConfig is a DB-backed configuration for a social login
// provider. Administrators manage providers at runtime via the admin API
// extension; the generic OAuth2 client reads these rows to build providers.
type SocialProviderConfig struct {
	gorm.Model
	ProviderID   string `gorm:"uniqueIndex;not null;size:64"` // e.g. "google", "github"
	DisplayName  string `gorm:"not null;size:128"`            // e.g. "Google"
	ClientID     string `gorm:"not null;size:256"`            // OAuth2 client ID
	ClientSecret string `gorm:"not null;size:512"`            // OAuth2 client secret
	Scopes       datatypes.JSON `gorm:"type:json"`            // JSON array of OAuth2 scopes
	AuthURL      string `gorm:"size:512"`                     // authorization endpoint
	TokenURL     string `gorm:"size:512"`                     // token endpoint
	UserURL      string `gorm:"size:512"`                     // userinfo endpoint
	UserIDKey    string `gorm:"size:64"`                      // JSON key for user id in userinfo
	UserEmailKey string `gorm:"size:64"`                      // JSON key for email in userinfo
	UserNameKey  string `gorm:"size:64"`                      // JSON key for name in userinfo
	Enabled      bool   `gorm:"default:false"`                // whether this provider is active
	OrderIndex   int    `gorm:"default:0"`                    // display ordering
}

// GetScopes deserializes the JSON scopes column into a []string.
func (c *SocialProviderConfig) GetScopes() []string {
	var scopes []string
	if len(c.Scopes) > 0 {
		_ = json.Unmarshal(c.Scopes, &scopes)
	}
	return scopes
}

// SetScopes serializes a []string into the JSON scopes column.
func (c *SocialProviderConfig) SetScopes(scopes []string) error {
	if scopes == nil {
		c.Scopes = nil
		return nil
	}
	data, err := json.Marshal(scopes)
	if err != nil {
		return err
	}
	c.Scopes = data
	return nil
}
