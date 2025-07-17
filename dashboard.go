package dashboard

import (
	"embed"
	_ "embed"
	"fmt"
	"go.lumeweb.com/portal-plugin-dashboard/build"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api"
	pluginConfig "go.lumeweb.com/portal-plugin-dashboard/internal/config"
	"go.lumeweb.com/portal-plugin-dashboard/internal/db/migrations"
	"go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
	pluginService "go.lumeweb.com/portal-plugin-dashboard/internal/service"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/portal/service"
	"go.lumeweb.com/web/go/portal-plugin-dashboard"
)

//go:embed templates/*
var mailerTemplates embed.FS

func init() {
	templates, err := service.MailerTemplatesFromEmbed(&mailerTemplates, "")
	if err != nil {
		panic(err)
	}

	core.RegisterPlugin(core.PluginInfo{
		ID:      internal.PLUGIN_NAME,
		Version: build.GetInfo(),
		Depends: []string{"core"},
		Meta: func(ctx core.Context, builder core.PortalMetaBuilder) error {
			pluginCfg := ctx.Config().GetAPI(internal.PLUGIN_NAME).(*pluginConfig.APIConfig)

			// Get the plugin builder for the dashboard plugin using the new Plugin method
			pluginBuilder, err := builder.Plugin(internal.PLUGIN_NAME)
			if err != nil {
				return fmt.Errorf("failed to get plugin meta builder for dashboard: %w", err)
			}

			if pluginCfg.SocialLogin.Enabled {
				builder.AddFeatureFlag("social_login", true)
				pluginBuilder.AddMeta("social_providers", provider.EnabledProviders())
			}

			pluginBuilder.AddMeta("subdomain", pluginCfg.Subdomain)
			pluginBuilder.AddMeta("themes", pluginCfg.Themes)
			return nil
		},
		API: func() (core.API, []core.ContextBuilderOption, error) {
			return api.NewAPI()
		},
		Services: func() ([]core.ServiceInfo, error) {
			return []core.ServiceInfo{
				{
					ID: pluginService.API_KEY_SERVICE,
					Factory: func() (core.Service, []core.ContextBuilderOption, error) {
						return pluginService.NewAPIKeyService()
					},
					Depends: []string{core.USER_SERVICE, core.AUTH_SERVICE},
				},
			}, nil
		},
		Models: []any{
			&models.APIKey{},
		},

		Migrations: core.DBMigration{
			core.DB_TYPE_MYSQL:  migrations.GetMySQL(),
			core.DB_TYPE_SQLITE: migrations.GetSQLite(),
		},
		MailerTemplates: templates,
		WebBundles:      core.NewWebBundles(core.NewWebBundle(portal_plugin_dashboard.GetFS(), core.WithWebBundleTargetApps("dashboard"))),
	})
}
