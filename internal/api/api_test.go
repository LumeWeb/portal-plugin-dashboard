package api

import (
	"testing"

	pluginCore "go.lumeweb.com/portal-plugin-dashboard/core"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	pluginConfig "go.lumeweb.com/portal-plugin-dashboard/internal/config"
	coreTesting "go.lumeweb.com/portal/core/testing"
)

func TestMain(m *testing.M) {
	// Use the new framework's TestMain helper to set up the shared environment.
	// We use WithOptions because these tests do not require a real database.
	coreTesting.WithOptions(m,
		// Configure the domain for the API
		coreTesting.WithConfig("core.domain", "example.com"),
		// Register the Dashboard API using the helper
		coreTesting.WithAPI(internal.PLUGIN_NAME, NewAPI),
		coreTesting.WithConfig("plugin.dashboard.api.subdomain", "account"),
		coreTesting.WithAPIConfig(internal.PLUGIN_NAME, &pluginConfig.APIConfig{
			Subdomain: "account",
		}),
		// Explicitly add the APIKeyService mock, as it's not in the core defaults
		coreTesting.WithMockServiceFactory(pluginCore.API_KEY_SERVICE, pluginCore.NewMockAPIKeyService),
	)
}
