package keyidentity

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/mr-tron/base58"

	"go.lumeweb.com/portal-plugin-dashboard/internal/caip122"
	pluginConfig "go.lumeweb.com/portal-plugin-dashboard/internal/config"
	"go.lumeweb.com/portal/core"
)
// SolanaMainnetGenesis is the CAIP-2 chain_id for Solana mainnet.
const SolanaMainnetChainID = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"

// SolanaHandler handles Solana address-based key identities.
//
// Key = Solana address (base58-encoded 32-byte Ed25519 public key).
// Metadata = JSON object, may contain "chain_id" (CAIP-2 string, e.g.,
// "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp").
//
// The handler implements the CAIP-122 Solana profile challenge/verify lifecycle:
//   - IssueChallenge: generates a nonce, stores it, and returns a SIWS message
//     template for the client to sign.
//   - VerifyProof: parses the signed SIWS message, validates nonce/domain/expiry,
//     verifies the Ed25519 signature against the claimed public key.
type SolanaHandler struct {
	mu        sync.RWMutex
	store     caip122.ChallengeStore
	closeOnce sync.Once
	closed    bool
}

// NewSolanaHandler creates a SolanaHandler with an in-memory challenge store.
func NewSolanaHandler() *SolanaHandler {
	return &SolanaHandler{
		store: caip122.NewMemoryChallengeStore(),
	}
}

// SetStore replaces the challenge store.
func (h *SolanaHandler) SetStore(store caip122.ChallengeStore) {
	if store == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	oldStore := h.store
	h.store = store
	if closer, ok := oldStore.(io.Closer); ok {
		_ = closer.Close()
	}
}

// Close stops the background reaper goroutine.
func (h *SolanaHandler) Close() error {
	h.closeOnce.Do(func() {
		h.mu.Lock()
		if closer, ok := h.store.(io.Closer); ok {
			_ = closer.Close()
		}
		h.closed = true
		h.mu.Unlock()
	})
	return nil
}

func (h *SolanaHandler) getStore() caip122.ChallengeStore {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.store
}

// NormalizeKey validates and canonicalizes a Solana address.
// The key must be a base58-encoded 32-byte Ed25519 public key.
// Returns the canonical base58 re-encoding to ensure consistent representation.
func (h *SolanaHandler) NormalizeKey(key string) (string, error) {
	decoded, err := base58.Decode(key)
	if err != nil {
		return "", fmt.Errorf("solana: invalid base58 address: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return "", fmt.Errorf("solana: invalid address length: expected %d bytes, got %d", ed25519.PublicKeySize, len(decoded))
	}
	// Re-encode to ensure canonical form
	return base58.Encode(decoded), nil
}

// solanaMetadata is the typed schema for Solana KeyIdentity metadata.
type solanaMetadata struct {
	ChainID string `json:"chain_id,omitempty"`
}

// ValidateMetadata validates the metadata JSON for a Solana key identity.
// If chain_id is present, it must be a valid CAIP-2 solana: identifier.
// If absent, defaults to mainnet.
func (h *SolanaHandler) ValidateMetadata(metadata json.RawMessage) (json.RawMessage, error) {
	if len(metadata) == 0 {
		return json.RawMessage(`{}`), nil
	}

	var m solanaMetadata
	if err := json.Unmarshal(metadata, &m); err != nil {
		return nil, fmt.Errorf("solana: invalid metadata JSON: %w", err)
	}

	if m.ChainID != "" {
		if !strings.HasPrefix(m.ChainID, "solana:") {
			return nil, fmt.Errorf("solana: chain_id must be CAIP-2 format (solana:<genesis>), got %q", m.ChainID)
		}
		genesis := strings.TrimPrefix(m.ChainID, "solana:")
		if genesis == "" {
			return nil, fmt.Errorf("solana: chain_id must be CAIP-2 format (solana:<genesis>), got %q", m.ChainID)
		}
	}

	canonical, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("solana: failed to canonicalize metadata: %w", err)
	}
	return json.RawMessage(canonical), nil
}

// extractChainID validates metadata and extracts the chain_id.
// Returns the validated chain_id, or SolanaMainnetChainID if not present.
func (h *SolanaHandler) extractChainID(metadata json.RawMessage) (string, error) {
	validated, err := h.ValidateMetadata(metadata)
	if err != nil {
		return "", err
	}

	chainID := SolanaMainnetChainID
	var m solanaMetadata
	if err := json.Unmarshal(validated, &m); err == nil && m.ChainID != "" {
		chainID = m.ChainID
	}
	return chainID, nil
}

// IssueChallenge generates a CAIP-122 challenge for proving ownership of the
// given Solana address. Returns a JSON payload with nonce and SIWS message.
func (h *SolanaHandler) IssueChallenge(ctx core.Context, key string, metadata json.RawMessage) ([]byte, error) {
	normalized, err := h.NormalizeKey(key)
	if err != nil {
		return nil, err
	}

	chainID, err := h.extractChainID(metadata)
	if err != nil {
		return nil, err
	}

	domain := h.resolveDomain(ctx)
	if domain == "" {
		return nil, fmt.Errorf("solana: cannot determine dashboard domain for CAIP-122 challenge")
	}

	challenge := caip122.NewChallengeService(h.getStore(), caip122.DefaultChallengeConfig(domain))

	nonce, err := challenge.GenerateChallenge(ctx)
	if err != nil {
		return nil, fmt.Errorf("solana: failed to generate challenge: %w", err)
	}

	message, err := caip122.FormatSolanaMessage(normalized, domain, nonce, chainID, caip122.DefaultChallengeConfig(domain).TTL)
	if err != nil {
		return nil, fmt.Errorf("solana: failed to construct SIWS message: %w", err)
	}

	response, err := caip122.EncodeSolanaChallengeResponse(nonce, message)
	if err != nil {
		return nil, fmt.Errorf("solana: failed to marshal challenge response: %w", err)
	}

	return response, nil
}

// VerifyProof verifies a CAIP-122 signed message as proof of Solana address ownership.
//
// The proof parameter is a JSON payload:
//   {"message": "<SIWS plaintext>", "signature": "<base58 Ed25519 sig>"}
//
// The handler validates nonce/domain/expiry, verifies the Ed25519 signature
// against the claimed public key, and compares the address in the message
// to the claimed key.
func (h *SolanaHandler) VerifyProof(ctx core.Context, key string, metadata json.RawMessage, proof []byte) error {
	var payload struct {
		Message   string `json:"message"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(proof, &payload); err != nil {
		return fmt.Errorf("solana: invalid proof payload: %w", err)
	}

	if payload.Message == "" || payload.Signature == "" {
		return fmt.Errorf("solana: proof payload must contain 'message' and 'signature' fields")
	}

	normalized, err := h.NormalizeKey(key)
	if err != nil {
		return err
	}

	chainID, err := h.extractChainID(metadata)
	if err != nil {
		return err
	}

	// Verify the chain_id in the signed message matches the registered metadata
	// before consuming the nonce, so an invalid chain_id doesn't delete a
	// legitimate challenge.
	parsed, err := caip122.ParseSolanaMessage(payload.Message)
	if err != nil {
		return fmt.Errorf("solana: invalid proof message: %w", err)
	}
	msgChainID := "solana:" + parsed.GetChainID()
	if msgChainID != chainID {
		return fmt.Errorf("solana: chain_id mismatch (expected %s, got %s)", chainID, msgChainID)
	}

	address, err := caip122.VerifySolanaChallengeParsed(ctx, h.getStore(), parsed, payload.Signature)
	if err != nil {
		return fmt.Errorf("solana: proof verification failed: %w", err)
	}

	// Verify the address from the signed message matches the claimed key.
	// Both should be canonical base58 at this point.
	if address != normalized {
		return fmt.Errorf("solana: address mismatch (expected %s, got %s)", normalized, address)
	}

	return nil
}

// resolveDomain extracts the full dashboard domain from core.Context config.
// Same logic as EthereumHandler.resolveDomain.
func (h *SolanaHandler) resolveDomain(ctx core.Context) string {
	if ctx == nil {
		return ""
	}
	cfg := ctx.Config()
	if cfg == nil {
		return ""
	}

	coreDomain := cfg.Config().Core.Domain

	pluginCfg := cfg.GetAPI("dashboard")
	if apiCfg, ok := pluginCfg.(*pluginConfig.APIConfig); ok {
		if coreDomain == "" {
			return apiCfg.Subdomain
		}
		return apiCfg.Subdomain + "." + coreDomain
	}
	return coreDomain
}

// SolanaHandlerRegistration returns the PluginInfo registration entry for
// the Solana key identity handler.
func SolanaHandlerRegistration() core.KeyIdentityHandlerRegistration {
	return core.KeyIdentityHandlerRegistration{
		Type:    "solana",
		Handler: NewSolanaHandler(),
	}
}
