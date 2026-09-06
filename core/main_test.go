package service_test

import (
	"testing"

	pluginCore "go.lumeweb.com/portal-plugin-dashboard/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
)

func TestMain(m *testing.M) {
	coreTesting.WithOptions(m,
		coreTesting.WithConfig("core.domain", "example.com"),
		// Register the APIKeyService mock so NewAPIKeyUsageLogger can resolve it.
		coreTesting.WithMockServiceFactory(pluginCore.API_KEY_SERVICE, pluginCore.NewMockAPIKeyService),
	)
}
