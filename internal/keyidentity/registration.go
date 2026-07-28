package keyidentity

import (
	"go.lumeweb.com/portal/core"
	corekeyidentity "go.lumeweb.com/portal/core/keyidentity"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	pluginConfig "go.lumeweb.com/portal-plugin-dashboard/internal/config"
)

// dashboardDomainResolver resolves the CAIP-122 domain by combining the
// dashboard plugin's subdomain with the portal core domain.
type dashboardDomainResolver struct{}

func (dashboardDomainResolver) ResolveDomain(ctx core.Context) string {
	if ctx == nil {
		return ""
	}
	cfg := ctx.Config()
	if cfg == nil {
		return ""
	}

	rootCfg := cfg.Config()
	if rootCfg == nil {
		return ""
	}
	coreDomain := rootCfg.Core.Domain
	apiCfg := core.GetAPIConfig[*pluginConfig.APIConfig](ctx, internal.PLUGIN_NAME)
	if apiCfg == nil {
		return ""
	}
	return buildDomain(apiCfg.Subdomain, coreDomain)
}

// buildDomain combines a subdomain and core domain into a CAIP-122 domain,
// handling empty values without producing leading/trailing dots.
func buildDomain(subdomain, coreDomain string) string {
	if coreDomain == "" {
		return subdomain
	}
	if subdomain == "" {
		return coreDomain
	}
	return subdomain + "." + coreDomain
}

// EthereumHandlerRegistration returns the PluginInfo registration entry for
// the Ethereum key identity handler, configured with the dashboard's domain
// resolver.
func EthereumHandlerRegistration() core.KeyIdentityHandlerRegistration {
	return core.KeyIdentityHandlerRegistration{
		Type:    "ethereum",
		Handler: corekeyidentity.NewEthereumHandler(dashboardDomainResolver{}),
	}
}

// SolanaHandlerRegistration returns the PluginInfo registration entry for
// the Solana key identity handler, configured with the dashboard's domain
// resolver.
func SolanaHandlerRegistration() core.KeyIdentityHandlerRegistration {
	return core.KeyIdentityHandlerRegistration{
		Type:    "solana",
		Handler: corekeyidentity.NewSolanaHandler(dashboardDomainResolver{}),
	}
}
