package api

import (
	"testing"

	"go.lumeweb.com/portal-plugin-dashboard/internal"
	pluginConfig "go.lumeweb.com/portal-plugin-dashboard/internal/config"
	"go.lumeweb.com/portal-plugin-dashboard/internal/service"
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
		coreTesting.WithMockServiceFactory(service.API_KEY_SERVICE, service.NewMockAPIKeyService),
	)
}
