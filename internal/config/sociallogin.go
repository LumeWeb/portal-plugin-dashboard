package config

import "go.lumeweb.com/portal/config"

var _ config.APIConfig = (*SocialLogin)(nil)

type SocialLogin struct {
	Enabled  bool                      `config:"enabled"`
	Provider map[string]ProviderConfig `config:"provider"`
	Order    []string                  `config:"order"`
}

func (A SocialLogin) Defaults() map[string]any {
	return map[string]any{
		"Enabled": false,
	}
}
