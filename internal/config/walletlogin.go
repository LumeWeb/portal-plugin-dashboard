package config

import "go.lumeweb.com/portal/config"

var _ config.APIConfig = (*WalletLogin)(nil)

// WalletLogin controls whether wallet-based sign-in (key identity login) is
// exposed to the frontend. Disabled by default, mirroring SocialLogin.
type WalletLogin struct {
	Enabled bool `config:"enabled"`
}

func (W WalletLogin) Defaults() map[string]any {
	return map[string]any{
		"Enabled": false,
	}
}
