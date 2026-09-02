package config

import "go.lumeweb.com/portal/config"

var _ config.APIConfig = (*SocialLogin)(nil)

type SocialLogin struct {
	Enabled bool `config:"enabled"`
}

func (A SocialLogin) Defaults() map[string]any {
	return map[string]any{
		"Enabled": false,
	}
}
