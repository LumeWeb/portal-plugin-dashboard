package dto

import (
	z "github.com/Oudwins/zog"
	"go.lumeweb.com/httputil"
)

var (
	_ httputil.DTOValidator = (*LoginRequest)(nil)
	_ httputil.DTORequest[*LoginRequest] = (*LoginRequest)(nil)
	_ httputil.DTOResponse[*LoginResponse] = (*LoginResponse)(nil)
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Remember bool   `json:"remember"`
}

func (r *LoginRequest) Schema() *z.StructSchema {
	return z.Struct(z.Schema{
		"Email":    z.String().Required().Email(),
		"Password": z.String().Required().Min(8),
		"Remember": z.Bool().Optional(),
	})
}

func (r *LoginRequest) ToModel() (*LoginRequest, error) {
	return r, nil
}

type LoginResponse struct {
	Token string `json:"token"`
	Otp   bool   `json:"otp,omitempty"`
}

func (r *LoginResponse) FromModel(model *LoginResponse) error {
	r.Token = model.Token
	r.Otp = model.Otp
	return nil
}
