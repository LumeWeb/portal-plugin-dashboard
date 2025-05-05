package config

import (
	"errors"
	"fmt"
	"go.lumeweb.com/portal/config"
)

var _ config.Validator = (*Theme)(nil)
var _ config.Validator = (*Color)(nil)

type Color struct {
	Hue        int `config:"hue" json:"hue"`
	Saturation int `config:"saturation" json:"saturation"`
	Lightness  int `config:"lightness" json:"lightness"`
}

func (c Color) Validate() error {
	if c.Hue < 0 || c.Hue > 360 {
		return fmt.Errorf("hue must be between 0 and 360, got %d", c.Hue)
	}
	if c.Saturation < 0 || c.Saturation > 100 {
		return fmt.Errorf("saturation must be between 0 and 100, got %d", c.Saturation)
	}
	if c.Lightness < 0 || c.Lightness > 100 {
		return fmt.Errorf("lightness must be between 0 and 100, got %d", c.Lightness)
	}
	return nil
}

type SystemColors struct {
	Background           Color `config:"background" json:"background" yaml:"background"`
	SubtleBackground     Color `config:"subtle_background" json:"subtle_background" yaml:"subtle_background"`
	UIElementBackground  Color `config:"ui_element_background" json:"ui_element_background" yaml:"ui_element_background"`
	HoveredUIElement     Color `config:"hovered_ui_element" json:"hovered_ui_element" yaml:"hovered_ui_element"`
	ActiveUIElement      Color `config:"active_ui_element" json:"active_ui_element" yaml:"active_ui_element"`
	Borders              Color `config:"borders" json:"borders" yaml:"borders"`
	UIElementBorder      Color `config:"ui_element_border" json:"ui_element_border" yaml:"ui_element_border"`
	HoveredElementBorder Color `config:"hovered_element_border" json:"hovered_element_border" yaml:"hovered_element_border"`
	SolidBackground      Color `config:"solid_background" json:"solid_background" yaml:"solid_background"`
	HoveredSolidBg       Color `config:"hovered_solid_bg" json:"hovered_solid_bg" yaml:"hovered_solid_bg"`
	LowContrastText      Color `config:"low_contrast_text" json:"low_contrast_text" yaml:"low_contrast_text"`
	HighContrastText     Color `config:"high_contrast_text" json:"high_contrast_text" yaml:"high_contrast_text"`
}

type BackgroundImages struct {
	Register      string `config:"register" json:"register" yaml:"register"`
	ResetPassword string `config:"reset_password" json:"reset_password" yaml:"reset_password"`
	Login         string `config:"login" json:"login" yaml:"login"`
}

type Theme struct {
	Name             string           `config:"name" json:"name" yaml:"name"`
	ID               string           `config:"id" json:"id" yaml:"id"`
	SystemColors     SystemColors     `config:"system_colors" json:"system_colors" yaml:"system_colors"`
	BackgroundImages BackgroundImages `config:"background_images" json:"background_images" yaml:"background_images"`
	Default          bool             `config:"default" json:"default" yaml:"default"`
}

func (t Theme) Validate() error {
	if t.Name == "" {
		return errors.New("theme name is required")
	}
	return nil
}

func defaultThemeConfig() []Theme {
	return []Theme{
		{
			Name: "Blue",
			ID:   "blue",
			SystemColors: SystemColors{
				Background:           Color{247, 0, 0},
				SubtleBackground:     Color{249, 0, 2},
				UIElementBackground:  Color{248, 47, 10},
				HoveredUIElement:     Color{250, 65, 5},
				ActiveUIElement:      Color{249, 52, 9},
				Borders:              Color{248, 35, 32},
				UIElementBorder:      Color{248, 30, 19},
				HoveredElementBorder: Color{247, 31, 24},
				SolidBackground:      Color{248, 52, 29},
				HoveredSolidBg:       Color{246, 57, 31},
				LowContrastText:      Color{244, 50, 64},
				HighContrastText:     Color{237, 41, 74},
			},
			BackgroundImages: BackgroundImages{
				Register:      "",
				ResetPassword: "",
				Login:         "",
			},
		},
		{
			Name:    "Eclipse",
			ID:      "eclipse",
			Default: true,
			SystemColors: SystemColors{
				Background:           Color{173, 24, 7},
				SubtleBackground:     Color{175, 24, 9},
				UIElementBackground:  Color{174, 55, 11},
				HoveredUIElement:     Color{176, 93, 12},
				ActiveUIElement:      Color{175, 80, 16},
				Borders:              Color{174, 63, 21},
				UIElementBorder:      Color{174, 58, 26},
				HoveredElementBorder: Color{173, 59, 31},
				SolidBackground:      Color{174, 80, 36},
				HoveredSolidBg:       Color{172, 85, 38},
				LowContrastText:      Color{170, 90, 45},
				HighContrastText:     Color{163, 69, 81},
			},
			BackgroundImages: BackgroundImages{
				Register:      "",
				ResetPassword: "",
				Login:         "",
			},
		},
	}
}
