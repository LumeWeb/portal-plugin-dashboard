package config

import (
	z "github.com/Oudwins/zog"
	"go.lumeweb.com/portal/config"
)

var _ config.ConfigSchemaProvider = (*Branding)(nil)

type Branding struct {
	LogoURL    string `config:"logo_url" json:"logoUrl,omitempty"`
	FaviconURL string `config:"favicon_url" json:"faviconUrl,omitempty"`
}

func (b Branding) Schema() z.ZogSchema {
	return z.Struct(z.Shape{
		"LogoURL":    z.String(),
		"FaviconURL": z.String(),
	})
}
