package dto

import (
	z "github.com/Oudwins/zog"
	"go.lumeweb.com/httputil"
)

var (
	_ httputil.DTOValidator = (*PasswordResetRequest)(nil)
	_ httputil.DTOValidator = (*PasswordResetVerifyRequest)(nil)
	_ httputil.DTOValidator = (*UpdatePasswordRequest)(nil)
	_ httputil.DTORequest[*PasswordResetRequest] = (*PasswordResetRequest)(nil)
	_ httputil.DTORequest[*PasswordResetVerifyRequest] = (*PasswordResetVerifyRequest)(nil)
	_ httputil.DTORequest[*UpdatePasswordRequest] = (*UpdatePasswordRequest)(nil)
)

type PasswordResetRequest struct {
	Email string `json:"email"`
}

func (r *PasswordResetRequest) Schema() *z.StructSchema {
	return z.Struct(z.Schema{
		"Email": z.String().Required().Email(),
	})
}

type PasswordResetVerifyRequest struct {
	Email    string `json:"email"`
	Token    string `json:"token"`
	Password string `json:"password"`
}

func (r *PasswordResetVerifyRequest) Schema() *z.StructSchema {
	return z.Struct(z.Schema{
		"Email":    z.String().Required().Email(),
		"Token":    z.String().Required(),
		"Password": z.String().Required().Min(8),
	})
}

type UpdatePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (r *UpdatePasswordRequest) Schema() *z.StructSchema {
	return z.Struct(z.Schema{
		"CurrentPassword": z.String().Required().Min(8),
		"NewPassword":     z.String().Required().Min(8),
	})
}

func (r *PasswordResetRequest) ToModel() (*PasswordResetRequest, error) {
	return r, nil
}

func (r *PasswordResetVerifyRequest) ToModel() (*PasswordResetVerifyRequest, error) {
	return r, nil
}

func (r *UpdatePasswordRequest) ToModel() (*UpdatePasswordRequest, error) {
	return r, nil
}

var (
	_ httputil.DTORequest[*PasswordResetRequest] = (*PasswordResetRequest)(nil)
	_ httputil.DTORequest[*PasswordResetVerifyRequest] = (*PasswordResetVerifyRequest)(nil)
	_ httputil.DTORequest[*UpdatePasswordRequest] = (*UpdatePasswordRequest)(nil)
)
