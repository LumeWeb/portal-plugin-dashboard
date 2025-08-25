package dto

import (
	z "github.com/Oudwins/zog"
	"go.lumeweb.com/httputil"
)

var (
	_ httputil.DTOValidator                          = (*VerifyEmailRequest)(nil)
	_ httputil.DTOValidator                          = (*ResendVerifyEmailRequest)(nil)
	_ httputil.DTOValidator                          = (*UpdateEmailRequest)(nil)
	_ httputil.DTORequest[*VerifyEmailRequest]       = (*VerifyEmailRequest)(nil)
	_ httputil.DTORequest[*ResendVerifyEmailRequest] = (*ResendVerifyEmailRequest)(nil)
	_ httputil.DTORequest[*UpdateEmailRequest]       = (*UpdateEmailRequest)(nil)
)

type VerifyEmailRequest struct {
	Email string `json:"email"`
	Token string `json:"token"`
}

func (r *VerifyEmailRequest) Schema() *z.StructSchema {
	return z.Struct(z.Shape{
		"Email": z.String().Required().Email(),
		"Token": z.String().Required(),
	})
}

type ResendVerifyEmailRequest struct {
	Email string `json:"email"`
}

func (r *ResendVerifyEmailRequest) Schema() *z.StructSchema {
	return z.Struct(z.Shape{
		"Email": z.String().Required().Email(),
	})
}

type UpdateEmailRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (r *UpdateEmailRequest) Schema() *z.StructSchema {
	return z.Struct(z.Shape{
		"Email":    z.String().Required().Email(),
		"Password": z.String().Required().Min(8),
	})
}

func (r *VerifyEmailRequest) ToModel() (*VerifyEmailRequest, error) {
	return r, nil
}

func (r *ResendVerifyEmailRequest) ToModel() (*ResendVerifyEmailRequest, error) {
	return r, nil
}

func (r *UpdateEmailRequest) ToModel() (*UpdateEmailRequest, error) {
	return r, nil
}
