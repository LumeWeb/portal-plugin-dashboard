package messages

import (
	"github.com/google/uuid"
	"go.lumeweb.com/portal/core"
	"time"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Remember bool   `json:"remember"`
}

type LoginResponse struct {
	Token string `json:"token"`
	Otp   bool   `json:"otp,omitempty"`
}

type RegisterRequest struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Password  string `json:"password"`
}

type OTPGenerateResponse struct {
	OTP string `json:"otp"`
}

type OTPVerifyRequest struct {
	OTP string `json:"otp"`
}

type OTPValidateRequest struct {
	OTP string `json:"otp"`
}
type OTPDisableRequest struct {
	Password string `json:"password"`
}
type VerifyEmailRequest struct {
	Email string `json:"email"`
	Token string `json:"token"`
}
type ResendVerifyEmailRequest struct {
	Email string `json:"email"`
}
type PasswordResetRequest struct {
	Email string `json:"email"`
}
type PasswordResetVerifyRequest struct {
	Email    string `json:"email"`
	Token    string `json:"token"`
	Password string `json:"password"`
}

type PongResponse struct {
	Ping  string `json:"ping"`
	Token string `json:"token"`
}
type AccountInfoResponse struct {
	ID        uint   `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Verified  bool   `json:"verified"`
	OTP       bool   `json:"otp"`
}

type UploadLimitResponse struct {
	Limit uint64 `json:"limit"`
}
type UpdateEmailRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type UpdatePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type APIKeyCreateRequest struct {
	Name string `json:"name"`
}

type APIKey struct {
	UUID      uuid.UUID `json:"uuid"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type ListAPIKeyResponse struct {
	Data  []APIKey `json:"data"`
	Total int64    `json:"total"`
}

type CreateAPIKeyResponse struct {
	Token string           `json:"token"`
	UUID  types.BinaryUUID `json:"uuid"`
	Name  string           `json:"name"`
}
type AccountPermissionsResponse struct {
	Permissions []*core.AccessPolicy `json:"permissions"`
	Model       *core.AccessModel    `json:"model"`
}
