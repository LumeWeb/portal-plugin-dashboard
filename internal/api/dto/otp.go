package dto

import (
	z "github.com/Oudwins/zog"
	"go.lumeweb.com/httputil"
)

var (
	_ httputil.DTOValidator                      = (*OTPVerifyRequest)(nil)
	_ httputil.DTOValidator                      = (*OTPValidateRequest)(nil)
	_ httputil.DTOValidator                      = (*OTPDisableRequest)(nil)
	_ httputil.DTOResponse[*OTPGenerateResponse] = (*OTPGenerateResponse)(nil)
)

type OTPVerifyRequest struct {
	OTP string `json:"otp"`
}

func (r *OTPVerifyRequest) Schema() *z.StructSchema {
	return z.Struct(z.Shape{
		"OTP": z.String().Required().Len(6),
	})
}

type OTPValidateRequest struct {
	OTP string `json:"otp"`
}

func (r *OTPValidateRequest) Schema() *z.StructSchema {
	return z.Struct(z.Shape{
		"OTP": z.String().Required().Len(6),
	})
}

type OTPDisableRequest struct {
	Password string `json:"password"`
}

func (r *OTPDisableRequest) Schema() *z.StructSchema {
	return z.Struct(z.Shape{
		"Password": z.String().Required().Min(8),
	})
}

func (r *OTPVerifyRequest) ToModel() (*OTPVerifyRequest, error) {
	return r, nil
}

func (r *OTPValidateRequest) ToModel() (*OTPValidateRequest, error) {
	return r, nil
}

func (r *OTPDisableRequest) ToModel() (*OTPDisableRequest, error) {
	return r, nil
}

type OTPGenerateResponse struct {
	OTP string `json:"otp"`
}

func (r *OTPGenerateResponse) FromModel(model *OTPGenerateResponse) error {
	r.OTP = model.OTP
	return nil
}

var (
	_ httputil.DTORequest[*OTPVerifyRequest]   = (*OTPVerifyRequest)(nil)
	_ httputil.DTORequest[*OTPValidateRequest] = (*OTPValidateRequest)(nil)
	_ httputil.DTORequest[*OTPDisableRequest]  = (*OTPDisableRequest)(nil)
)
