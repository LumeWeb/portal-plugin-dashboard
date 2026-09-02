package social_provider

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pluginCore "go.lumeweb.com/portal-plugin-dashboard/core"
	pluginDbMigrations "go.lumeweb.com/portal-plugin-dashboard/internal/db/migrations"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	"go.lumeweb.com/portal/db"
)

func TestMain(m *testing.M) {
	// Register the provider model + migrations + service through the mock
	// plugin builder so the DB harness migrates and wires everything.
	pluginBuilder := coreTesting.NewMockPluginBuilder(pluginCore.SOCIAL_PROVIDER_SERVICE).
		WithMigrations(core.DBMigration{
			core.DB_TYPE_SQLITE: pluginDbMigrations.GetSQLite(),
		}).
		WithModels(&pluginDb.SocialProviderConfig{}).
		WithService(pluginCore.SOCIAL_PROVIDER_SERVICE, NewSocialProviderService)

	coreTesting.WithDBAndOptions(m,
		pluginBuilder.BuilderOption(),
	)
}

func TestSocialProviderService_CreateAndGet(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		svc := core.GetService[pluginCore.SocialProviderService](ctx, pluginCore.SOCIAL_PROVIDER_SERVICE)
		require.NotNil(tb, svc)

		cfg := &pluginDb.SocialProviderConfig{
			ProviderID:   "google",
			DisplayName:  "Google",
			ClientID:     "cid",
			ClientSecret: "sec",
			Enabled:      true,
		}
		require.NoError(tb, svc.Create(context.Background(), cfg))
		assert.NotZero(tb, cfg.ID)

		got, err := svc.Get(context.Background(), cfg.ID)
		require.NoError(tb, err)
		assert.Equal(tb, "google", got.ProviderID)
	})
}

func TestSocialProviderService_CreateDuplicateKey(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		svc := core.GetService[pluginCore.SocialProviderService](ctx, pluginCore.SOCIAL_PROVIDER_SERVICE)
		require.NotNil(tb, svc)

		mk := func() *pluginDb.SocialProviderConfig {
			return &pluginDb.SocialProviderConfig{
				ProviderID:   "github",
				DisplayName:  "GitHub",
				ClientID:     "cid",
				ClientSecret: "sec",
			}
		}
		require.NoError(tb, svc.Create(context.Background(), mk()))
		err := svc.Create(context.Background(), mk())
		require.Error(tb, err)
		assert.True(tb, db.IsDuplicateKeyError(err), "expected duplicate-key error, got %v", err)
	})
}

func TestSocialProviderService_ListEnabled(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		svc := core.GetService[pluginCore.SocialProviderService](ctx, pluginCore.SOCIAL_PROVIDER_SERVICE)
		require.NotNil(tb, svc)

		for _, cfg := range []*pluginDb.SocialProviderConfig{
			{ProviderID: "disabled", DisplayName: "Disabled", ClientID: "c", ClientSecret: "s", Enabled: false},
			{ProviderID: "google", DisplayName: "Google", ClientID: "c", ClientSecret: "s", Enabled: true, OrderIndex: 2},
			{ProviderID: "gitlab", DisplayName: "GitLab", ClientID: "c", ClientSecret: "s", Enabled: true, OrderIndex: 1},
		} {
			require.NoError(tb, svc.Create(context.Background(), cfg))
		}

		configs, err := svc.ListEnabled(context.Background())
		require.NoError(tb, err)
		require.Len(tb, configs, 2)
		// Ordered by order_index then display_name.
		assert.Equal(tb, "gitlab", configs[0].ProviderID)
		assert.Equal(tb, "google", configs[1].ProviderID)
	})
}

// Delete hard-deletes so the provider_id unique slot is freed for re-creation.
func TestSocialProviderService_DeleteFreesProviderID(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		svc := core.GetService[pluginCore.SocialProviderService](ctx, pluginCore.SOCIAL_PROVIDER_SERVICE)
		require.NotNil(tb, svc)

		mk := func() *pluginDb.SocialProviderConfig {
			return &pluginDb.SocialProviderConfig{
				ProviderID:   "github",
				DisplayName:  "GitHub",
				ClientID:     "cid",
				ClientSecret: "sec",
			}
		}

		cfg := mk()
		require.NoError(tb, svc.Create(context.Background(), cfg))

		rows, err := svc.Delete(context.Background(), cfg.ID)
		require.NoError(tb, err)
		assert.Equal(tb, int64(1), rows)

		// Re-creating the same provider_id must succeed (no stale soft-delete row).
		require.NoError(tb, svc.Create(context.Background(), mk()))
	})
}
