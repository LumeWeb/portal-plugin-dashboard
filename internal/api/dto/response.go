package dto

import (
	"time"

	z "github.com/Oudwins/zog"
	"go.lumeweb.com/portal/db/models"
	"go.lumeweb.com/portal/db/types"

	"go.lumeweb.com/httputil"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal/core"
)

var (
	_ httputil.DTOResponse[*PongResponse]        = (*PongResponse)(nil)
	_ httputil.DTOResponse[*models.User]         = (*AccountInfoResponse)(nil)
	_ httputil.DTOResponse[*UploadLimitResponse] = (*UploadLimitResponse)(nil)
	_ httputil.DTOResponse[*pluginDb.APIKey]     = (*APIKeyResponse)(nil)
	_ httputil.DTOResponse[*pluginDb.APIKey]     = (*CreateAPIKeyResponse)(nil)
	_ httputil.DTOResponse[PermissionsModel]     = (*AccountPermissionsResponse)(nil)
	_ httputil.DTOValidator                      = (*APIKeyCreateRequest)(nil)
	_ httputil.DTORequest[*APIKeyCreateRequest]  = (*APIKeyCreateRequest)(nil)
)

type APIKeyCreateRequest struct {
	Name string `json:"name"`
}

type UpdateProfileRequest struct {
	FirstName *string `json:"first_name,omitempty"`
	LastName  *string `json:"last_name,omitempty"`
}

func (r *UpdateProfileRequest) Schema() *z.StructSchema {
	return z.Struct(z.Shape{
		"FirstName": z.Ptr(z.String().Optional()),
		"LastName":  z.Ptr(z.String().Optional()),
	})
}

func (r *UpdateProfileRequest) ToModel() (*UpdateProfileRequest, error) {
	return r, nil
}

func (r *APIKeyCreateRequest) Schema() *z.StructSchema {
	return z.Struct(z.Shape{
		"Name": z.String().Required().Min(1),
	})
}

func (r *APIKeyCreateRequest) ToModel() (*APIKeyCreateRequest, error) {
	return r, nil
}

type PongResponse struct {
	Ping  string `json:"ping"`
	Token string `json:"token"`
}

func (r *PongResponse) FromModel(model *PongResponse) error {
	r.Ping = model.Ping
	r.Token = model.Token
	return nil
}

type AccountInfoResponse struct {
	ID        uint      `json:"id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Verified  bool      `json:"verified"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	OTP       bool      `json:"otp"`
	Avatar    string    `json:"avatar,omitempty"`
}

func (r *AccountInfoResponse) FromModel(user *models.User) error {
	r.ID = user.ID
	r.Email = user.Email
	r.FirstName = user.FirstName
	r.LastName = user.LastName
	r.Verified = user.Verified
	r.CreatedAt = user.CreatedAt
	r.OTP = user.OTPEnabled
	return nil
}

type UploadLimitResponse struct {
	Limit uint64 `json:"limit"`
}

func (r *UploadLimitResponse) FromModel(model *UploadLimitResponse) error {
	r.Limit = model.Limit
	return nil
}

type APIKeyResponse struct {
	UUID      types.BinaryUUID `json:"uuid"`
	Name      string           `json:"name"`
	CreatedAt time.Time        `json:"created_at"`
}

func (r *APIKeyResponse) FromModel(key *pluginDb.APIKey) error {
	r.UUID = key.UUID
	r.Name = key.Name
	r.CreatedAt = key.CreatedAt
	return nil
}

type CreateAPIKeyResponse struct {
	Token string           `json:"token"`
	UUID  types.BinaryUUID `json:"uuid"`
	Name  string           `json:"name"`
}

func (r *CreateAPIKeyResponse) FromModel(key *pluginDb.APIKey) error {
	r.Token = key.JWT
	r.UUID = key.UUID
	r.Name = key.Name
	return nil
}

type PermissionsModel struct {
	Permissions []*core.AccessPolicy
	Model       *core.AccessModel
}

type AvatarResponse struct {
	URL      string    `json:"url"`
	Uploaded time.Time `json:"uploaded"`
}

type AccountPermissionsResponse struct {
	Permissions []*core.AccessPolicy `json:"permissions"`
	Model       *core.AccessModel    `json:"model"`
}

func (r *AccountPermissionsResponse) FromModel(model PermissionsModel) error {
	r.Permissions = model.Permissions
	r.Model = model.Model
	return nil
}
