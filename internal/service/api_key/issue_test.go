package api_key

import (
	"context"
	"testing"
	"time"

	pluginCore "go.lumeweb.com/portal-plugin-dashboard/core"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestAPIKeyService_IssueAPIKey(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		apiKeyService := core.GetService[pluginCore.APIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, apiKeyService)

		userID := uint(1)
		ttl := time.Hour * 24 * 30

		issued, err := apiKeyService.IssueAPIKey(context.Background(), userID, "workspace-1", ttl)
		require.NoError(tb, err)
		require.NotNil(tb, issued)
		assert.NotZero(tb, issued.ID)
		assert.NotEmpty(tb, issued.Token)
		assert.Equal(tb, "workspace-1", issued.Name)
		assert.NotEqual(tb, issued.ExpiresAt.IsZero(), true, "expiry should be set")
		assert.True(tb, issued.ExpiresAt.After(time.Now()))

		// The row must be persisted with the expiry and user ownership.
		var fetched pluginDb.APIKey
		err = ctx.DB().First(&fetched, issued.ID).Error
		require.NoError(tb, err)
		assert.Equal(tb, issued.UUID.String(), fetched.UUID.ToUUID().String())
		assert.Equal(tb, userID, fetched.UserID)
		require.NotNil(tb, fetched.Expires)
		assert.WithinDuration(tb, issued.ExpiresAt, *fetched.Expires, time.Minute)

		// The token is a signed JWT, not the persisted row's raw JWT field.
		assert.NotEqual(tb, issued.Token, fetched.JWT)
	})
}

func TestAPIKeyService_ReissueAPIKey(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		apiKeyService := core.GetService[pluginCore.APIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, apiKeyService)

		userID := uint(1)
		key, err := apiKeyService.CreateAPIKey(context.Background(), userID, "workspace-1")
		require.NoError(tb, err)

		ttl := time.Hour
		issued, err := apiKeyService.ReissueAPIKey(context.Background(), userID, key.ID, ttl)
		require.NoError(tb, err)
		require.NotNil(tb, issued)
		assert.Equal(tb, key.ID, issued.ID)
		assert.Equal(tb, key.UUID.ToUUID(), issued.UUID)
		assert.NotEmpty(tb, issued.Token)
		assert.WithinDuration(tb, time.Now().Add(ttl), issued.ExpiresAt, time.Minute)

		// The expiry is refreshed on the same row.
		var fetched pluginDb.APIKey
		err = ctx.DB().First(&fetched, key.ID).Error
		require.NoError(tb, err)
		require.NotNil(tb, fetched.Expires)
		assert.WithinDuration(tb, issued.ExpiresAt, *fetched.Expires, time.Minute)
	})
}

func TestAPIKeyService_ReissueAPIKey_NotOwner(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		apiKeyService := core.GetService[pluginCore.APIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, apiKeyService)

		key, err := apiKeyService.CreateAPIKey(context.Background(), uint(1), "workspace-1")
		require.NoError(tb, err)

		// A different user must not be able to reissue another user's key.
		_, err = apiKeyService.ReissueAPIKey(context.Background(), uint(2), key.ID, time.Hour)
		require.ErrorIs(tb, err, gorm.ErrRecordNotFound)
	})
}

func TestAPIKeyService_RevokeAPIKey(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		apiKeyService := core.GetService[pluginCore.APIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, apiKeyService)

		userID := uint(1)
		key, err := apiKeyService.CreateAPIKey(context.Background(), userID, "workspace-1")
		require.NoError(tb, err)

		err = apiKeyService.RevokeAPIKey(context.Background(), userID, key.ID)
		require.NoError(tb, err)

		// The key is soft-deleted and no longer findable.
		var fetched pluginDb.APIKey
		err = ctx.DB().First(&fetched, key.ID).Error
		require.ErrorIs(tb, err, gorm.ErrRecordNotFound)
	})
}

func TestAPIKeyService_RevokeAPIKey_MissingIsNoOp(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		apiKeyService := core.GetService[pluginCore.APIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, apiKeyService)

		// Revoking a key another user owns (or that never existed) is treated
		// as already revoked and must not error.
		err := apiKeyService.RevokeAPIKey(context.Background(), uint(1), uint(9999))
		require.NoError(tb, err)
	})
}
