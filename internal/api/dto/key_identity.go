package dto

import (
	"encoding/json"

	z "github.com/Oudwins/zog"
	jsonschema "github.com/invopop/jsonschema"
	"go.lumeweb.com/httputil"
)

var (
	_ httputil.DTOValidator                               = (*KeyIdentityChallengeRequest)(nil)
	_ httputil.DTORequest[*KeyIdentityChallengeRequest]   = (*KeyIdentityChallengeRequest)(nil)
	_ httputil.DTOResponse[*KeyIdentityChallengeResponse] = (*KeyIdentityChallengeResponse)(nil)

	_ httputil.DTOValidator                            = (*KeyIdentityVerifyRequest)(nil)
	_ httputil.DTORequest[*KeyIdentityVerifyRequest]   = (*KeyIdentityVerifyRequest)(nil)
	_ httputil.DTOResponse[*KeyIdentityVerifyResponse] = (*KeyIdentityVerifyResponse)(nil)
)

// JSONRawMessageSchema represents a JSON object schema for json.RawMessage fields.
// This is necessary because gswagger cannot auto-generate schemas for json.RawMessage.
type JSONRawMessageSchema json.RawMessage

func (s JSONRawMessageSchema) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "object",
	}
}

// NewJSONRawMessageSchema creates a JSONRawMessageSchema from a byte slice.
func NewJSONRawMessageSchema(b []byte) JSONRawMessageSchema {
	return JSONRawMessageSchema(b)
}

// KeyIdentityChallengeRequest is the request body for issuing a key identity challenge.
type KeyIdentityChallengeRequest struct {
	KeyType  string               `json:"key_type"`
	Key      string               `json:"key"`
	Metadata JSONRawMessageSchema `json:"metadata,omitempty"`
}

func (r *KeyIdentityChallengeRequest) Schema() *z.StructSchema {
	return z.Struct(z.Shape{
		"KeyType": z.String().Required(),
		"Key":     z.String().Required(),
	})
}

func (r *KeyIdentityChallengeRequest) ToModel() (*KeyIdentityChallengeRequest, error) {
	return r, nil
}

// KeyIdentityChallengeResponse is the response body for a challenge request.
// The client must sign the `message` according to the key type's protocol
// (e.g., EIP-191 personal_sign for Ethereum) and return the signature
// along with the message via KeyIdentityVerifyRequest.
type KeyIdentityChallengeResponse struct {
	Message string `json:"message"`
	Nonce   string `json:"nonce"`
}

func (r *KeyIdentityChallengeResponse) FromModel(model *KeyIdentityChallengeResponse) error {
	r.Message = model.Message
	r.Nonce = model.Nonce
	return nil
}

// KeyIdentityVerifyRequest is the request body for verifying a signed challenge.
type KeyIdentityVerifyRequest struct {
	KeyType   string               `json:"key_type"`
	Key       string               `json:"key"`
	Metadata  JSONRawMessageSchema `json:"metadata,omitempty"`
	Message   string               `json:"message"`
	Signature string               `json:"signature"`
	Remember  bool                 `json:"remember"`
}

func (r *KeyIdentityVerifyRequest) Schema() *z.StructSchema {
	return z.Struct(z.Shape{
		"KeyType":   z.String().Required(),
		"Key":       z.String().Required(),
		"Message":   z.String().Required(),
		"Signature": z.String().Required(),
		"Remember":  z.Bool().Optional(),
	})
}

func (r *KeyIdentityVerifyRequest) ToModel() (*KeyIdentityVerifyRequest, error) {
	return r, nil
}

// KeyIdentityVerifyResponse is the response body for a successful verification.
// If the user has OTP enabled, `otp` will be true and the client must complete
// the OTP flow. Otherwise, the token is the JWT.
// If `new_account` is true, the verification provisioned a new anonymous
// account for a previously unseen wallet (redirects carry new_account=1).
type KeyIdentityVerifyResponse struct {
	Token      string `json:"token"`
	Otp        bool   `json:"otp,omitempty"`
	NewAccount bool   `json:"new_account,omitempty"`
}

func (r *KeyIdentityVerifyResponse) FromModel(model *KeyIdentityVerifyResponse) error {
	r.Token = model.Token
	r.Otp = model.Otp
	r.NewAccount = model.NewAccount
	return nil
}

// --- Identity Management DTOs (authenticated) ---

var (
	_ httputil.DTOValidator                                   = (*KeyIdentityConnectVerifyRequest)(nil)
	_ httputil.DTORequest[*KeyIdentityConnectVerifyRequest]   = (*KeyIdentityConnectVerifyRequest)(nil)
	_ httputil.DTOResponse[*KeyIdentityConnectVerifyResponse] = (*KeyIdentityConnectVerifyResponse)(nil)

	_ httputil.DTOResponse[*KeyIdentityListResponse] = (*KeyIdentityListResponse)(nil)
)

// KeyIdentityConnectVerifyRequest is the request body for verifying a signed
// challenge to link a new key identity to the authenticated user's account.
type KeyIdentityConnectVerifyRequest struct {
	KeyType   string               `json:"key_type"`
	Key       string               `json:"key"`
	Metadata  JSONRawMessageSchema `json:"metadata,omitempty"`
	Message   string               `json:"message"`
	Signature string               `json:"signature"`
}

func (r *KeyIdentityConnectVerifyRequest) Schema() *z.StructSchema {
	return z.Struct(z.Shape{
		"KeyType":   z.String().Required(),
		"Key":       z.String().Required(),
		"Message":   z.String().Required(),
		"Signature": z.String().Required(),
	})
}

func (r *KeyIdentityConnectVerifyRequest) ToModel() (*KeyIdentityConnectVerifyRequest, error) {
	return r, nil
}

// KeyIdentityConnectVerifyResponse is the response body for a successful
// key identity connection.
type KeyIdentityConnectVerifyResponse struct {
	KeyType  string               `json:"key_type"`
	Key      string               `json:"key"`
	Metadata JSONRawMessageSchema `json:"metadata,omitempty"`
}

func (r *KeyIdentityConnectVerifyResponse) FromModel(model *KeyIdentityConnectVerifyResponse) error {
	r.KeyType = model.KeyType
	r.Key = model.Key
	r.Metadata = model.Metadata
	return nil
}

// KeyIdentityItem represents a single key identity in list responses.
type KeyIdentityItem struct {
	KeyType  string               `json:"key_type"`
	Key      string               `json:"key"`
	Metadata JSONRawMessageSchema `json:"metadata,omitempty"`
}

// KeyIdentityListResponse is the response body for listing key identities.
type KeyIdentityListResponse struct {
	Identities []KeyIdentityItem `json:"identities"`
}

func (r *KeyIdentityListResponse) FromModel(model *KeyIdentityListResponse) error {
	r.Identities = model.Identities
	return nil
}
