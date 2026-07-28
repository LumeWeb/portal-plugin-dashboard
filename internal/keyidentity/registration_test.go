package keyidentity

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.lumeweb.com/portal/core"
	pluginConfig "go.lumeweb.com/portal-plugin-dashboard/internal/config"
	coreTesting "go.lumeweb.com/portal/core/testing"
)

func TestMain(m *testing.M) {
	coreTesting.WithOptions(m,
		coreTesting.WithConfig("plugin.dashboard.api.subdomain", "account"),
		coreTesting.WithAPIConfig("dashboard", &pluginConfig.APIConfig{
			Subdomain: "account",
		}),
	)
}

// TestEthereumHandlerRegistration verifies the registration entry has the
// correct type string and a non-nil handler wired to the dashboardDomainResolver.
func TestEthereumHandlerRegistration(t *testing.T) {
	reg := EthereumHandlerRegistration()
	assert.Equal(t, "ethereum", reg.Type)
	assert.NotNil(t, reg.Handler)

	var _ core.KeyIdentityHandler = reg.Handler
}

// TestSolanaHandlerRegistration verifies the registration entry has the
// correct type string and a non-nil handler.
func TestSolanaHandlerRegistration(t *testing.T) {
	reg := SolanaHandlerRegistration()
	assert.Equal(t, "solana", reg.Type)
	assert.NotNil(t, reg.Handler)

	var _ core.KeyIdentityHandler = reg.Handler
}

// TestDashboardDomainResolver_NilContext verifies the resolver returns an
// empty string when the context is nil, rather than panicking.
func TestDashboardDomainResolver_NilContext(t *testing.T) {
	r := dashboardDomainResolver{}
	assert.Empty(t, r.ResolveDomain(nil))
}

// TestDashboardDomainResolver_FullDomain verifies that when both the
// dashboard API subdomain and core domain are present, the resolver
// combines them as "subdomain.coredomain".
func TestDashboardDomainResolver_FullDomain(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		r := dashboardDomainResolver{}
		domain := r.ResolveDomain(ctx)
		assert.Equal(t, "account.test.local", domain)
	})
}

// TestDashboardDomainResolver_EmptyCoreDomain verifies that when the core
// domain is empty but the subdomain is set, the resolver returns just the
// subdomain (no trailing dot).
func TestDashboardDomainResolver_EmptyCoreDomain(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ctx.Config().Config().Core.Domain = ""
		r := dashboardDomainResolver{}
		domain := r.ResolveDomain(ctx)
		assert.Equal(t, "account", domain)
	})
}

// TestDashboardDomainResolver_EmptySubdomain verifies that when the
// subdomain is empty but the core domain is set, the resolver returns
// just the core domain (no leading dot). This is a regression test for
// the leading-dot bug where "" + "." + "example.com" produced ".example.com".
func TestDashboardDomainResolver_EmptySubdomain(t *testing.T) {
	// We can't set Subdomain="" via config options because validation
	// requires it. Instead, test the logic directly by constructing a
	// resolver that returns an empty subdomain from the API config.
	// The resolver logic is: if subdomain == "" return coreDomain.
	// Verify that the concatenation never produces a leading dot.
	tests := []struct {
		subdomain  string
		coreDomain string
		expected   string
	}{
		{"", "example.com", "example.com"},
		{"account", "", "account"},
		{"account", "example.com", "account.example.com"},
		{"", "", ""},
	}
	for _, tt := range tests {
		got := buildDomain(tt.subdomain, tt.coreDomain)
		assert.Equal(t, tt.expected, got, "subdomain=%q coreDomain=%q", tt.subdomain, tt.coreDomain)
		assert.False(t, strings.HasPrefix(got, "."), "domain must not start with a dot: %q", got)
	}
}

// TestEthereumHandlerRegistration_ExercisesProductionResolver issues a
// challenge through the production registration path and verifies the domain
// in the resulting SIWE message matches the dashboard domain (subdomain +
// core domain), not the bare core domain. This catches bugs where the
// dashboardDomainResolver is bypassed.
func TestEthereumHandlerRegistration_ExercisesProductionResolver(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		reg := EthereumHandlerRegistration()
		require.NotNil(t, reg.Handler)

		challenge, err := reg.Handler.IssueChallenge(ctx, "0x1234567890123456789012345678901234567890", nil)
		require.NoError(t, err)

		assert.Contains(t, string(challenge), "account.test.local",
			"challenge should use the dashboard domain (subdomain + core), not the bare core domain")
		assert.NotContains(t, string(challenge), "portal.local",
			"challenge should not use the bare core domain when subdomain is configured")
	})
}

// TestSolanaHandlerRegistration_ExercisesProductionResolver issues a challenge
// through the production registration path and verifies the domain in the
// resulting SIWS message matches the dashboard domain.
func TestSolanaHandlerRegistration_ExercisesProductionResolver(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		reg := SolanaHandlerRegistration()
		require.NotNil(t, reg.Handler)

		// Valid Solana address (32-byte zero-padded base58 — the system program)
		solAddr := "11111111111111111111111111111112"
		challenge, err := reg.Handler.IssueChallenge(ctx, solAddr, nil)
		require.NoError(t, err)

		assert.Contains(t, string(challenge), "account.test.local",
			"challenge should use the dashboard domain (subdomain + core), not the bare core domain")
		assert.NotContains(t, string(challenge), "portal.local",
			"challenge should not use the bare core domain when subdomain is configured")
	})
}
