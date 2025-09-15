package api

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/gif"
	"image/jpeg"
	"image/png"
	"testing"

	_ "golang.org/x/image/webp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessAvatar(t *testing.T) {
	tests := []struct {
		name        string
		inputFormat string
		inputSize   image.Rectangle
		wantFormat  string
		wantSize    image.Rectangle
	}{
		{
			name:        "JPEG input - Large Square",
			inputFormat: "image/jpeg",
			inputSize:   image.Rect(0, 0, 500, 500),
			wantFormat:  "image/webp",
			wantSize:    image.Rect(0, 0, AvatarWidth, AvatarHeight),
		},
		{
			name:        "PNG input - Tall",
			inputFormat: "image/png",
			inputSize:   image.Rect(0, 0, 300, 600),
			wantFormat:  "image/webp",
			wantSize:    image.Rect(0, 0, AvatarWidth, AvatarHeight),
		},
		{
			name:        "GIF input - Wide",
			inputFormat: "image/gif",
			inputSize:   image.Rect(0, 0, 800, 400),
			wantFormat:  "image/webp",
			wantSize:    image.Rect(0, 0, AvatarWidth, AvatarHeight),
		},
		{
			name:        "JPEG input - Small Square",
			inputFormat: "image/jpeg",
			inputSize:   image.Rect(0, 0, 100, 100),
			wantFormat:  "image/webp",
			wantSize:    image.Rect(0, 0, AvatarWidth, AvatarHeight),
		},
		{
			name:        "PNG input - Large Landscape",
			inputFormat: "image/png",
			inputSize:   image.Rect(0, 0, 1200, 800),
			wantFormat:  "image/webp",
			wantSize:    image.Rect(0, 0, AvatarWidth, AvatarHeight),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test image
			img := image.NewRGBA(tt.inputSize)
			draw.Draw(img, img.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)

			var buf bytes.Buffer
			switch tt.inputFormat {
			case "image/jpeg":
				err := jpeg.Encode(&buf, img, nil)
				require.NoError(t, err)
			case "image/png":
				err := png.Encode(&buf, img)
				require.NoError(t, err)
			case "image/gif":
				err := gif.Encode(&buf, img, nil)
				require.NoError(t, err)
			}

			// Process the image
			processed, mimeType, err := processAvatar(buf.Bytes())
			require.NoError(t, err)
			assert.Equal(t, tt.wantFormat, mimeType)

			// Verify output image properties
			decodedImg, _, err := image.Decode(bytes.NewReader(processed))
			require.NoError(t, err)
			assert.Equal(t, tt.wantSize, decodedImg.Bounds())
		})
	}
}

func TestProcessAvatar_InvalidInput(t *testing.T) {
	_, _, err := processAvatar([]byte("not an image"))
	assert.Error(t, err)
}
