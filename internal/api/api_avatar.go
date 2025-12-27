package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"golang.org/x/image/draw"
	_ "golang.org/x/image/webp"

	"github.com/gabriel-vasile/mimetype"
	"github.com/kolesa-team/go-webp/encoder"
	"github.com/kolesa-team/go-webp/webp"
	"github.com/labstack/echo/v4"
	"go.lumeweb.com/httputil"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	router "go.lumeweb.com/portal-router"
	"go.lumeweb.com/portal/core"
	"go.uber.org/zap"
)

const (
	AvatarUploadDir  = "avatars"
	AvatarMimeTypes  = "image/jpeg,image/png,image/gif,image/webp" // Still accept all types but convert to WebP
	AvatarMaxSize    = 5 << 20                                     // 5MB
	AvatarWidth      = 120
	AvatarHeight     = 120
	AvatarPathFormat = "%s/%d.webp"            // Format string for avatar paths
	AvatarURLFormat  = "%s/api/account/avatar" // Format string for avatar URLs
)

func (a *API) buildAvatarRoutes(authMw echo.MiddlewareFunc, accessMw echo.MiddlewareFunc) []router.Route {
	return []router.Route{
		router.NewRoute(http.MethodPost, "/api/account/avatar", a.uploadAvatar,
			router.WithSwaggerOptions(
				router.WithSummary("Upload Avatar"),
				router.WithDescription("Uploads a profile picture/avatar"),
				router.WithFileUpload("Avatar file to upload", true),
				router.WithSuccessResponse(http.StatusNoContent, "Avatar uploaded"),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
		router.NewRoute(http.MethodGet, "/api/account/avatar", a.getAvatar,
			router.WithSwaggerOptions(
				router.WithSummary("Get Avatar"),
				router.WithDescription("Retrieves the authenticated user's profile picture"),
				router.WithSuccessResponse(http.StatusOK, "Avatar image"),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
	}
}

func (a *API) uploadAvatar(c echo.Context) error {
	ctx := httputil.Context(c)
	userID, ok := a.getUser(ctx)
	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	upload, err := ctx.PrepareFileUpload(AvatarMaxSize)
	if err != nil {
		return ctx.Error(err, http.StatusBadRequest)
	}

	defer func(src io.ReadSeekCloser) {
		err := src.Close()
		if err != nil {
			a.logger.Error("failed to close avatar file", zap.Error(err))
		}
	}(upload.File)

	// Read original image data
	imgData, err := io.ReadAll(upload.File)
	if err != nil {
		return ctx.Error(fmt.Errorf("failed to read avatar file: %w", err), http.StatusBadRequest)
	}

	// MIME sniffing and whitelist check
	mime := mimetype.Detect(imgData)
	if err := a.validateMimeType(mime.String()); err != nil {
		return ctx.Error(fmt.Errorf("invalid avatar file type: %w", err), http.StatusBadRequest)
	}

	// Check for decompression bombs by validating pixel count
	const maxPixels = 10000000 // 10 megapixels
	config, _, err := image.DecodeConfig(bytes.NewReader(imgData))
	if err != nil {
		return ctx.Error(fmt.Errorf("failed to decode avatar image config: %w", err), http.StatusBadRequest)
	}
	if config.Width*config.Height > maxPixels {
		return ctx.Error(fmt.Errorf("avatar image exceeds maximum pixel count of %d", maxPixels), http.StatusBadRequest)
	}

	// Process and resize image
	resizedImg, _, err := processAvatar(imgData)
	if err != nil {
		return ctx.Error(fmt.Errorf("failed to process avatar: %w", err), http.StatusBadRequest)
	}

	// Generate storage path
	path, err := a.getAvatarPath(userID)
	if err != nil {
		return ctx.Error(err, http.StatusBadRequest)
	}

	// Store in S3
	storage := core.GetService[core.StorageService](a.Context(), core.STORAGE_SERVICE)
	err = storage.S3Upload(ctx.Request().Context(),
		a.S3Bucket(),
		path,
		bytes.NewReader(resizedImg))
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		return ctx.Error(err, http.StatusInternalServerError)
	}

	return c.NoContent(http.StatusNoContent)
}

func (a *API) getAvatar(c echo.Context) error {
	ctx := httputil.Context(c)
	userID, ok := a.getUser(ctx)
	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	storage := core.GetService[core.StorageService](a.Context(), core.STORAGE_SERVICE)

	reader, mimeType, err := a.getAvatarReader(storage, ctx.Request().Context(), userID)
	if err == nil {
		defer func(reader io.ReadCloser) {
			err := reader.Close()
			if err != nil {
				a.logger.Error("failed to close avatar reader", zap.Error(err))
			}
		}(reader)
		ct := "application/octet-stream"
		if mimeType != nil {
			ct = mimeType.String()
		}
		return c.Stream(http.StatusOK, ct, reader)
	}

	return ctx.Error(fmt.Errorf("avatar not found"), http.StatusNotFound)
}

func (a *API) setAvatarURL(ctx httputil.RequestContext, userID uint, responseDto *dto.AccountInfoResponse) error {
	storage := core.GetService[core.StorageService](a.Context(), core.STORAGE_SERVICE)
	path, err := a.getAvatarPath(userID)
	if err != nil {
		return err
	}
	exists, err := storage.S3Exists(ctx.Request().Context(), a.S3Bucket(), path)
	if err != nil {
		return err
	}
	if exists {
		host := a.http.APISubdomain(a.Name(), true)
		responseDto.Avatar = fmt.Sprintf(AvatarURLFormat, host)
	}
	return nil
}

func (a *API) getAvatarPath(userID uint) (string, error) {
	return fmt.Sprintf(AvatarPathFormat, AvatarUploadDir, userID), nil
}

func (a *API) getAvatarReader(storage core.StorageService, ctx context.Context, userID uint) (io.ReadCloser, *mimetype.MIME, error) {
	path, err := a.getAvatarPath(userID)
	if err != nil {
		return nil, nil, err
	}
	reader, err := storage.S3Download(ctx, a.S3Bucket(), path)
	if err == nil {
		return reader, mimetype.Lookup(".webp"), nil
	}

	// Check for AWS S3 "not found" errors and map them to 404
	var notFound *types.NotFound
	var apiErr smithy.APIError
	if errors.As(err, &notFound) ||
		(errors.As(err, &apiErr) &&
			(apiErr.ErrorCode() == "NotFound" || apiErr.ErrorCode() == "NoSuchKey")) {
		return nil, nil, fmt.Errorf("avatar not found")
	}

	// For all other errors, wrap and return so handler can map to 5xx
	return nil, nil, fmt.Errorf("failed to download avatar: %w", err)
}

func processAvatar(imgData []byte) ([]byte, string, error) {
	// Decode image
	decodedImg, _, err := image.Decode(bytes.NewReader(imgData))
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode image: %w", err)
	}
	img := decodedImg

	// Create thumbnail canvas
	thumb := image.NewRGBA(image.Rect(0, 0, AvatarWidth, AvatarHeight))

	// Calculate scaling factors
	srcBounds := img.Bounds()
	srcAspect := float64(srcBounds.Dx()) / float64(srcBounds.Dy())
	dstAspect := float64(AvatarWidth) / float64(AvatarHeight)

	var scale float64
	var srcX, srcY, srcW, srcH int

	if srcAspect > dstAspect {
		// Source is wider - crop sides
		scale = float64(AvatarHeight) / float64(srcBounds.Dy())
		srcW = int(float64(AvatarWidth) / scale)
		srcH = srcBounds.Dy()
		srcX = (srcBounds.Dx() - srcW) / 2
		srcY = 0
	} else {
		// Source is taller - crop top/bottom
		scale = float64(AvatarWidth) / float64(srcBounds.Dx())
		srcW = srcBounds.Dx()
		srcH = int(float64(AvatarHeight) / scale)
		srcX = 0
		srcY = (srcBounds.Dy() - srcH) / 2
	}

	// Resize and crop
	draw.CatmullRom.Scale(thumb, thumb.Bounds(), img, image.Rect(srcX, srcY, srcX+srcW, srcY+srcH), draw.Over, nil)

	// Encode as WebP using kolesa-team encoder
	var buf bytes.Buffer
	options, err := encoder.NewLossyEncoderOptions(encoder.PresetDefault, 85)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create WebP encoder options: %w", err)
	}

	if err := webp.Encode(&buf, thumb, options); err != nil {
		return nil, "", fmt.Errorf("failed to encode WebP: %w", err)
	}

	return buf.Bytes(), "image/webp", nil
}

func (a *API) validateMimeType(mimeType string) error {
	allowed := strings.Split(AvatarMimeTypes, ",")
	for _, a := range allowed {
		if a == mimeType {
			return nil
		}
	}
	return fmt.Errorf("invalid mime type %s, allowed: %s", mimeType, AvatarMimeTypes)
}
