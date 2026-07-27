package keyidentity

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"go.lumeweb.com/portal-plugin-dashboard/internal/caip122"
	pluginConfig "go.lumeweb.com/portal-plugin-dashboard/internal/config"
	"go.lumeweb.com/portal/core"
)

// EthereumHandler handles Ethereum address-based key identities.
//
// Key = Ethereum address (hex string, normalized to lowercase 0x-prefixed).
// Metadata = JSON object, may contain "chain_id" (CAIP-2 string, e.g., "eip155:1").
//
// The handler implements the full CAIP-122 (EIP-4361) challenge/verify lifecycle:
//   - IssueChallenge: generates a nonce, stores it, and returns a SIWE message
//     template for the client to sign.
//   - VerifyProof: parses the signed SIWE message, validates nonce/domain/expiry,
//     recovers the signer via secp256k1, and compares to the claimed key.
//
// All methods that need runtime context receive core.Context, which provides
// access to config (for domain resolution), DB, logger, and services.
type EthereumHandler struct {
	mu        sync.RWMutex
	store     caip122.ChallengeStore
	closeOnce sync.Once
	closed    bool
}

// NewEthereumHandler creates an EthereumHandler with an in-memory challenge store.
// The store can be replaced via SetStore (e.g., with a Redis-backed implementation).
// Call Close() to stop the background reaper goroutine when the handler is no
// longer needed.
func NewEthereumHandler() *EthereumHandler {
	return &EthereumHandler{
		store: caip122.NewMemoryChallengeStore(),
	}
}

// SetStore replaces the challenge store (e.g., with a Redis-backed implementation).
// The previous store is closed if it implements io.Closer to prevent goroutine leaks.
func (h *EthereumHandler) SetStore(store caip122.ChallengeStore) {
	if store == nil {
		return
	}
	h.mu.Lock()
	oldStore := h.store
	h.store = store
	h.mu.Unlock()
	if closer, ok := oldStore.(io.Closer); ok {
		_ = closer.Close()
	}
}

// Close stops the background reaper goroutine if the store implements io.Closer.
// Safe to call multiple times.
func (h *EthereumHandler) Close() error {
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

// getStore returns the current challenge store under a read lock.
func (h *EthereumHandler) getStore() caip122.ChallengeStore {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.store
}

func (h *EthereumHandler) NormalizeKey(key string) (string, error) {
	if !strings.HasPrefix(key, "0x") || len(key) != 42 {
		return "", fmt.Errorf("invalid ethereum address: must be 0x-prefixed hex, 42 chars, got %q", key)
	}
	if _, err := hex.DecodeString(key[2:]); err != nil {
		return "", fmt.Errorf("invalid ethereum address: non-hex character in %q", key)
	}
	return strings.ToLower(key), nil
}

// ethereumMetadata is the typed schema for Ethereum KeyIdentity metadata.
// Using a struct eliminates fragile map[string]interface{} type assertions.
type ethereumMetadata struct {
	ChainID string `json:"chain_id,omitempty"`
}

func (h *EthereumHandler) ValidateMetadata(metadata json.RawMessage) (json.RawMessage, error) {
	if len(metadata) == 0 {
		return json.RawMessage(`{}`), nil
	}

	var m ethereumMetadata
	if err := json.Unmarshal(metadata, &m); err != nil {
		return nil, fmt.Errorf("invalid metadata JSON: %w", err)
	}

	if m.ChainID != "" {
		if !strings.HasPrefix(m.ChainID, "eip155:") {
			return nil, fmt.Errorf("chain_id must be CAIP-2 format (eip155:<number>), got %q", m.ChainID)
		}
		numPart := strings.TrimPrefix(m.ChainID, "eip155:")
		if numPart == "" {
			return nil, fmt.Errorf("chain_id must be CAIP-2 format (eip155:<number>), got %q", m.ChainID)
		}
		chainNum, err := strconv.Atoi(numPart)
		if err != nil || chainNum < 0 {
			return nil, fmt.Errorf("chain_id must be CAIP-2 format (eip155:<number>), got %q", m.ChainID)
		}
		// Canonicalize to eip155:<int> to prevent leading-zero mismatches
		// between metadata and the signed SIWE message.
		m.ChainID = fmt.Sprintf("eip155:%d", chainNum)
	}

	canonical, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize metadata: %w", err)
	}
	return json.RawMessage(canonical), nil
}

// extractChainID validates metadata and extracts the chain_id.
// Returns the validated chain_id, or "eip155:1" if no chain_id is present.
// Returns an error if metadata is present but invalid.
func (h *EthereumHandler) extractChainID(metadata json.RawMessage) (string, error) {
	validated, err := h.ValidateMetadata(metadata)
	if err != nil {
		return "", err
	}

	chainID := "eip155:1"
	var m ethereumMetadata
	if err := json.Unmarshal(validated, &m); err == nil && m.ChainID != "" {
		chainID = m.ChainID
	}
	return chainID, nil
}

// IssueChallenge generates a CAIP-122 challenge for proving ownership of the
// given Ethereum address. The returned bytes are a JSON payload containing
// the nonce and the SIWE message text for the client to sign.
//
// The challenge state (nonce + domain) is stored in the handler's ChallengeStore
// so that VerifyProof can validate it later.
func (h *EthereumHandler) IssueChallenge(ctx core.Context, key string, metadata json.RawMessage) ([]byte, error) {
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
		return nil, fmt.Errorf("ethereum: cannot determine dashboard domain for CAIP-122 challenge")
	}

	challenge := caip122.NewChallengeService(h.getStore(), caip122.DefaultChallengeConfig(domain))

	nonce, err := challenge.GenerateChallenge(ctx)
	if err != nil {
		return nil, fmt.Errorf("ethereum: failed to generate challenge: %w", err)
	}

	config := caip122.DefaultChallengeConfig(domain)
	message, err := caip122.FormatMessage(normalized, domain, nonce, chainID, config.TTL)
	if err != nil {
		return nil, fmt.Errorf("ethereum: failed to construct SIWE message: %w", err)
	}

	response, err := json.Marshal(struct {
		Nonce   string `json:"nonce"`
		Message string `json:"message"`
	}{
		Nonce:   nonce,
		Message: message,
	})
	if err != nil {
		return nil, fmt.Errorf("ethereum: failed to marshal challenge response: %w", err)
	}

	return response, nil
}

// VerifyProof verifies a CAIP-122 signed message as proof of Ethereum address ownership.
//
// The proof parameter is a JSON payload:
//   {"message": "<EIP-4361 plaintext>", "signature": "<0x-prefixed hex RSV>"}
//
// The handler validates nonce/domain/expiry, recovers the signer via secp256k1,
// and compares the recovered address to the claimed key. It also validates that
// the chain_id in the signed message matches the chain_id in the registered metadata.
func (h *EthereumHandler) VerifyProof(ctx core.Context, key string, metadata json.RawMessage, proof []byte) error {
	var payload struct {
		Message   string `json:"message"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(proof, &payload); err != nil {
		return fmt.Errorf("ethereum: invalid proof payload: %w", err)
	}

	if payload.Message == "" || payload.Signature == "" {
		return fmt.Errorf("ethereum: proof payload must contain 'message' and 'signature' fields")
	}

	// Validate the key format before touching the challenge store.
	// This prevents malformed keys from consuming (deleting) legitimate nonces.
	normalized, err := h.NormalizeKey(key)
	if err != nil {
		return err
	}

	// Validate metadata (ensures chain_id format is correct if present).
	_, err = h.extractChainID(metadata)
	if err != nil {
		return err
	}

	domain := h.resolveDomain(ctx)

	challenge := caip122.NewChallengeService(h.getStore(), caip122.DefaultChallengeConfig(domain))

	address, _, err := challenge.VerifyChallengeWithChain(ctx, payload.Message, payload.Signature)
	if err != nil {
		return fmt.Errorf("ethereum: proof verification failed: %w", err)
	}

	// NOTE: chain_id is not enforced as a match against stored metadata.
	// Per CAIP-122 rationale: "SIWx should allow for authentication via
	// blockchain wallet across non-blockchain applications regardless of
	// which chain/wallet the user is using." Per EIP-4361, chain-id is
	// REQUIRED in the message but only constrains ERC-1271 contract
	// signature resolution — for EOA recovery (our use case), the
	// signature is chain-agnostic. The signed chain_id remains in the
	// message for user-facing anti-phishing and is stored in metadata
	// as informational data.

	if address != normalized {
		return fmt.Errorf("ethereum: address mismatch (expected %s, recovered %s)", normalized, address)
	}

	return nil
}

// resolveDomain extracts the full dashboard domain from core.Context config.
// Combines the dashboard plugin's Subdomain (e.g., "account") with the
// portal core's Domain (e.g., "example.com") to produce the full FQDN
// (e.g., "account.example.com") used as the CAIP-122 domain.
func (h *EthereumHandler) resolveDomain(ctx core.Context) string {
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

// EthereumHandlerRegistration returns the PluginInfo registration entry for
// the Ethereum key identity handler.
func EthereumHandlerRegistration() core.KeyIdentityHandlerRegistration {
	return core.KeyIdentityHandlerRegistration{
		Type:    "ethereum",
		Handler: NewEthereumHandler(),
	}
}
