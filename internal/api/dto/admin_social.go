package dto

import (
	"errors"
	"time"

	"go.lumeweb.com/httputil"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
)

var _ httputil.DTORequest[*SocialProviderRequest] = (*SocialProviderRequest)(nil)

// SocialProviderRequest is the admin payload for creating a social login
// provider. Updates use SocialProviderUpdateRequest, whose patch semantics do
// not require re-sending the secret.
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

// SocialProviderUpdateRequest is the admin payload for updating a social login
// provider. All fields are pointers so the API can distinguish "omitted" from
// "explicitly set": nil means leave the stored value unchanged, a non-nil
// value is applied. This gives callers true patch semantics even though the
// route is a PUT — the API never returns ClientSecret, so a full-replace
// contract would force callers to re-enter the secret on every edit.
//
// ClientSecret follows the same nil-means-keep rule, but an explicit empty
// string is rejected: clearing a secret would permanently break the provider,
// and since secrets are never returned there is no way to restore it.
type SocialProviderUpdateRequest struct {
	ProviderID   *string   `json:"provider_id,omitempty"`
	DisplayName  *string   `json:"display_name,omitempty"`
	ClientID     *string   `json:"client_id,omitempty"`
	ClientSecret *string   `json:"client_secret,omitempty"`
	Scopes       *[]string `json:"scopes,omitempty"`
	AuthURL      *string   `json:"auth_url,omitempty"`
	TokenURL     *string   `json:"token_url,omitempty"`
	UserURL      *string   `json:"user_url,omitempty"`
	UserIDKey    *string   `json:"user_id_key,omitempty"`
	UserEmailKey *string   `json:"user_email_key,omitempty"`
	UserNameKey  *string   `json:"user_name_key,omitempty"`
	Enabled      *bool     `json:"enabled,omitempty"`
	OrderIndex   *int      `json:"order_index,omitempty"`
}

// ToModel implements httputil.DTORequest, returning the request unchanged.
func (r *SocialProviderUpdateRequest) ToModel() (*SocialProviderUpdateRequest, error) {
	return r, nil
}

// Apply merges the update request onto an existing provider config using patch
// semantics: every non-nil field overwrites the config value, nil fields are
// left untouched. Scopes follow the same rule, with a non-nil empty slice
// clearing all scopes. It returns an error for values that would leave the
// provider unusable (an empty ClientSecret).
func (r *SocialProviderUpdateRequest) Apply(cfg *pluginDb.SocialProviderConfig) error {
	if r.ClientSecret != nil && *r.ClientSecret == "" {
		return errors.New("client_secret cannot be cleared")
	}
	if r.ProviderID != nil && *r.ProviderID == "" {
		return errors.New("provider_id cannot be empty")
	}
	if r.ClientID != nil && *r.ClientID == "" {
		return errors.New("client_id cannot be empty")
	}
	if r.ProviderID != nil {
		cfg.ProviderID = *r.ProviderID
	}
	if r.DisplayName != nil {
		cfg.DisplayName = *r.DisplayName
	}
	if r.ClientID != nil {
		cfg.ClientID = *r.ClientID
	}
	if r.ClientSecret != nil {
		cfg.ClientSecret = *r.ClientSecret
	}
	if r.AuthURL != nil {
		cfg.AuthURL = *r.AuthURL
	}
	if r.TokenURL != nil {
		cfg.TokenURL = *r.TokenURL
	}
	if r.UserURL != nil {
		cfg.UserURL = *r.UserURL
	}
	if r.UserIDKey != nil {
		cfg.UserIDKey = *r.UserIDKey
	}
	if r.UserEmailKey != nil {
		cfg.UserEmailKey = *r.UserEmailKey
	}
	if r.UserNameKey != nil {
		cfg.UserNameKey = *r.UserNameKey
	}
	if r.Enabled != nil {
		cfg.Enabled = *r.Enabled
	}
	if r.OrderIndex != nil {
		cfg.OrderIndex = *r.OrderIndex
	}
	if r.Scopes != nil {
		return cfg.SetScopes(*r.Scopes)
	}
	return nil
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

// SocialProviderListResponse is a swagger-only DTO that represents the paginated
// response for social providers. It mirrors the generic queryutil.Response[*dto.SocialProviderResponse]
// produced by queryutilHttp.ProcessListRequest for OpenAPI documentation.
//
// Note: This struct is only used for swagger documentation, not for actual encoding.
type SocialProviderListResponse struct {
	Data  []SocialProviderResponse `json:"data"`
	Total int64                    `json:"total"`
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
