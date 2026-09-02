package dto

import (
	"time"

	"go.lumeweb.com/httputil"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
)

var _ httputil.DTORequest[*SocialProviderRequest] = (*SocialProviderRequest)(nil)

// SocialProviderRequest is the admin payload for creating or updating a social
// login provider. ClientSecret is optional on update; an empty value keeps the
// existing secret.
type SocialProviderRequest struct {
	ProviderID   string   `json:"provider_id"`
	DisplayName  string   `json:"display_name"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes"`
	AuthURL      string   `json:"auth_url"`
	TokenURL     string   `json:"token_url"`
	UserURL      string   `json:"user_url"`
	UserIDKey    string   `json:"user_id_key"`
	UserEmailKey string   `json:"user_email_key"`
	UserNameKey  string   `json:"user_name_key"`
	Enabled      *bool    `json:"enabled"`
	OrderIndex   *int     `json:"order_index"`
}

// ToModel implements httputil.DTORequest, returning the request unchanged.
func (r *SocialProviderRequest) ToModel() (*SocialProviderRequest, error) {
	return r, nil
}

// SocialProviderResponse is the admin response for a social login provider.
// ClientSecret is intentionally omitted.
type SocialProviderResponse struct {
	ID           uint      `json:"id"`
	ProviderID   string    `json:"provider_id"`
	DisplayName  string    `json:"display_name"`
	ClientID     string    `json:"client_id"`
	Scopes       []string  `json:"scopes"`
	AuthURL      string    `json:"auth_url"`
	TokenURL     string    `json:"token_url"`
	UserURL      string    `json:"user_url"`
	UserIDKey    string    `json:"user_id_key"`
	UserEmailKey string    `json:"user_email_key"`
	UserNameKey  string    `json:"user_name_key"`
	Enabled      bool      `json:"enabled"`
	OrderIndex   int       `json:"order_index"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// FromModel populates the response from a provider config row.
func (r *SocialProviderResponse) FromModel(m *pluginDb.SocialProviderConfig) {
	r.ID = m.ID
	r.ProviderID = m.ProviderID
	r.DisplayName = m.DisplayName
	r.ClientID = m.ClientID
	r.Scopes = m.GetScopes()
	r.AuthURL = m.AuthURL
	r.TokenURL = m.TokenURL
	r.UserURL = m.UserURL
	r.UserIDKey = m.UserIDKey
	r.UserEmailKey = m.UserEmailKey
	r.UserNameKey = m.UserNameKey
	r.Enabled = m.Enabled
	r.OrderIndex = m.OrderIndex
	r.CreatedAt = m.CreatedAt
	r.UpdatedAt = m.UpdatedAt
}
