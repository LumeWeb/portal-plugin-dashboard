package dto

import (
	z "github.com/Oudwins/zog"
	"go.lumeweb.com/httputil"
)

var (
	_ httputil.DTOValidator                 = (*RegisterRequest)(nil)
	_ httputil.DTORequest[*RegisterRequest] = (*RegisterRequest)(nil)
)

type RegisterRequest struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Password  string `json:"password"`
}

func (r *RegisterRequest) Schema() *z.StructSchema {
	return z.Struct(z.Shape{
		"FirstName": z.String().Required().Min(1),
		"LastName":  z.String().Required().Min(1),
		"Email":     z.String().Required().Email(),
		"Password":  z.String().Required().Min(8),
	})
}

func (r *RegisterRequest) ToModel() (*RegisterRequest, error) {
	return r, nil
}
