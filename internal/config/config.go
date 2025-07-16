package config

import (
	z "github.com/Oudwins/zog"
	"github.com/Oudwins/zog/internals"
	"go.lumeweb.com/portal/config"
)

var _ config.APIConfig = (*APIConfig)(nil)

type Themes []Theme

type APIConfig struct {
	Subdomain   string      `config:"subdomain"`
	SocialLogin SocialLogin `config:"social_login"`
	AppFolder   string      `config:"app_folder"`
	Themes      Themes      `config:"themes"`
}

func (a APIConfig) Schema() z.ZogSchema {
	return z.Struct(z.Shape{
		"Subdomain": z.String().Required(),
		"AppFolder": z.String(),
		"Themes": z.Slice(z.Struct(z.Shape{})).TestFunc(func(val any, ctx internals.Ctx) bool {
			def := false
			for _, theme := range val.(Themes) {
				if theme.Default {
					if def {
						ctx.AddIssue(ctx.Issue().SetMessage("only one theme can be default"))
						return false
					}
					def = true
				}
			}
			return true
		}),
	})
}

func (A APIConfig) Defaults() map[string]any {
	return map[string]any{
		"Subdomain": "account",
		"Themes":    defaultThemeConfig(),
	}
}
