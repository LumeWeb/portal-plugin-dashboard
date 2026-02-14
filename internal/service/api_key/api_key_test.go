package api_key

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	pluginDbMigrations "go.lumeweb.com/portal-plugin-dashboard/internal/db/migrations"
	pluginCore "go.lumeweb.com/portal-plugin-dashboard/core"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	"go.lumeweb.com/queryutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gorm.io/gorm"
)

func TestMain(m *testing.M) {
	// Create a mock plugin with migrations and the api_key service
	pluginBuilder := coreTesting.NewMockPluginBuilder(pluginCore.API_KEY_SERVICE).
		WithMigrations(core.DBMigration{
			core.DB_TYPE_SQLITE: pluginDbMigrations.GetSQLite(),
		}).
		WithModels(&pluginDb.APIKey{}).
		WithService(pluginCore.API_KEY_SERVICE, NewAPIKeyService)

	coreTesting.WithDBAndOptions(m,
		pluginBuilder.BuilderOption(),
	)
}

func TestAPIKeyService_CreateAPIKey(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		apiKeyService := core.GetService[pluginCore.APIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, apiKeyService)

		userID := uint(1)
		name := "My Test Key"

		apiKey, err := apiKeyService.CreateAPIKey(context.Background(), userID, name)
		require.NoError(tb, err)
		assert.NotNil(tb, apiKey)

		assert.Equal(tb, name, apiKey.Name)
		assert.Equal(tb, userID, apiKey.UserID)
		assert.NotNil(tb, apiKey.UUID)

		// Verify it exists in the database
		var fetchedKey pluginDb.APIKey
		result := ctx.DB().First(&fetchedKey, apiKey.ID)
		require.NoError(tb, result.Error)
		assert.Equal(tb, apiKey.ID, fetchedKey.ID)
		assert.Equal(tb, apiKey.UUID, fetchedKey.UUID)
		assert.Equal(tb, apiKey.Name, fetchedKey.Name)
		assert.Equal(tb, apiKey.UserID, fetchedKey.UserID)

	})
}

func TestAPIKeyService_CreateAPIKey_DuplicateName(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		apiKeyService := core.GetService[pluginCore.APIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, apiKeyService)

		userID := uint(1)
		name := "My Test Key"

		// Create the first API key
		apiKey1, err := apiKeyService.CreateAPIKey(context.Background(), userID, name)
		require.NoError(tb, err)
		assert.NotNil(tb, apiKey1)

		// Create a second API key with the same name
		apiKey2, err := apiKeyService.CreateAPIKey(context.Background(), userID, name)
		require.NoError(tb, err)
		assert.NotNil(tb, apiKey2)

		// Verify that the UUIDs are different
		assert.NotEqual(tb, apiKey1.UUID, apiKey2.UUID)

		// Verify that both keys exist in the database
		var fetchedKey1 pluginDb.APIKey
		result := ctx.DB().First(&fetchedKey1, apiKey1.ID)
		require.NoError(tb, result.Error)
		assert.Equal(tb, apiKey1.ID, fetchedKey1.ID)

		var fetchedKey2 pluginDb.APIKey
		result = ctx.DB().First(&fetchedKey2, apiKey2.ID)
		require.NoError(tb, result.Error)
		assert.Equal(tb, apiKey2.ID, fetchedKey2.ID)

	})
}

func TestAPIKeyService_GetAPIKeys(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		apiKeyService := core.GetService[pluginCore.APIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, apiKeyService)

		userID1 := uint(1)
		userID2 := uint(2)

		// Create keys for user 1
		key1, err := apiKeyService.CreateAPIKey(context.Background(), userID1, "Key 1 User 1")
		require.NoError(tb, err)
		key2, err := apiKeyService.CreateAPIKey(context.Background(), userID1, "Key 2 User 1")
		require.NoError(tb, err)

		// Create key for user 2
		key3, err := apiKeyService.CreateAPIKey(context.Background(), userID2, "Key 1 User 2")
		require.NoError(tb, err)

		// Test fetching all keys for user 1
		filters := []queryutil.CrudFilter{}
		sorts := []queryutil.Sort{}
		pagination := queryutil.DefaultPagination

		keys, total, err := apiKeyService.GetAPIKeys(context.Background(), userID1, filters, sorts, pagination)
		require.NoError(tb, err)
		assert.Equal(tb, int64(2), total)
		assert.Len(tb, keys, 2)

		// Check if the correct keys are returned (order might vary without sort)
		foundKey1 := false
		foundKey2 := false
		for _, k := range keys {
			if k.UUID == key1.UUID {
				foundKey1 = true
			}
			if k.UUID == key2.UUID {
				foundKey2 = true
			}
			assert.Equal(tb, userID1, k.UserID) // Ensure only user1's keys are returned
		}
		assert.True(tb, foundKey1)
		assert.True(tb, foundKey2)

		// Test fetching keys for user 2
		keys, total, err = apiKeyService.GetAPIKeys(context.Background(), userID2, filters, sorts, pagination)
		require.NoError(tb, err)
		assert.Equal(tb, int64(1), total)
		assert.Len(tb, keys, 1)
		assert.Equal(tb, key3.UUID, keys[0].UUID)
		assert.Equal(tb, userID2, keys[0].UserID)

		// Test fetching keys for a user with no keys
		keys, total, err = apiKeyService.GetAPIKeys(context.Background(), uint(99), filters, sorts, pagination)
		require.NoError(tb, err)
		assert.Equal(tb, int64(0), total)
		assert.Len(tb, keys, 0)

	})
}

func TestAPIKeyService_GetAPIKeys_FilterByName(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		apiKeyService := core.GetService[pluginCore.APIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, apiKeyService)

		userID := uint(1)

		// Create keys
		key1, err := apiKeyService.CreateAPIKey(context.Background(), userID, "Key 1")
		require.NoError(tb, err)
		key2, err := apiKeyService.CreateAPIKey(context.Background(), userID, "Key 2")
		require.NoError(tb, err)

		// Test with filter
		nameFilter := queryutil.Equal("name", "Key 1")
		filters := []queryutil.CrudFilter{nameFilter}
		sorts := []queryutil.Sort{}
		pagination := queryutil.DefaultPagination

		keys, total, err := apiKeyService.GetAPIKeys(context.Background(), userID, filters, sorts, pagination)
		require.NoError(tb, err)
		assert.Equal(tb, int64(1), total)
		assert.Len(tb, keys, 1)
		assert.Equal(tb, key1.UUID, keys[0].UUID)

		// Test with no matching filter
		nameFilter = queryutil.Equal("name", "NonExistentKey")
		filters = []queryutil.CrudFilter{nameFilter}

		keys, total, err = apiKeyService.GetAPIKeys(context.Background(), userID, filters, sorts, pagination)
		require.NoError(tb, err)
		assert.Equal(tb, int64(0), total)
		assert.Len(tb, keys, 0)

		// Clean up
		err = apiKeyService.DeleteAPIKey(context.Background(), userID, key1.UUID.ToUUID())
		require.NoError(tb, err)
		err = apiKeyService.DeleteAPIKey(context.Background(), userID, key2.UUID.ToUUID())
		require.NoError(tb, err)
	})
}

func TestAPIKeyService_GetAPIKeys_SortByNameAscending(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		apiKeyService := core.GetService[pluginCore.APIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, apiKeyService)

		userID := uint(1)

		// Create keys
		key1, err := apiKeyService.CreateAPIKey(context.Background(), userID, "Key B")
		require.NoError(tb, err)
		key2, err := apiKeyService.CreateAPIKey(context.Background(), userID, "Key A")
		require.NoError(tb, err)

		// Test with sort
		sorts := []queryutil.Sort{{Field: "name", Order: queryutil.OrderAsc}}
		filters := []queryutil.CrudFilter{}
		pagination := queryutil.DefaultPagination

		keys, total, err := apiKeyService.GetAPIKeys(context.Background(), userID, filters, sorts, pagination)
		require.NoError(tb, err)
		assert.Equal(tb, int64(2), total)
		assert.Len(tb, keys, 2)
		assert.Equal(tb, key2.UUID, keys[0].UUID) // Key A should come first
		assert.Equal(tb, key1.UUID, keys[1].UUID) // Key B should come second

		// Clean up
		err = apiKeyService.DeleteAPIKey(context.Background(), userID, key1.UUID.ToUUID())
		require.NoError(tb, err)
		err = apiKeyService.DeleteAPIKey(context.Background(), userID, key2.UUID.ToUUID())
		require.NoError(tb, err)
	})
}

func TestAPIKeyService_GetAPIKeys_SortByNameDescending(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		apiKeyService := core.GetService[pluginCore.APIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, apiKeyService)

		userID := uint(1)

		// Create keys
		key1, err := apiKeyService.CreateAPIKey(context.Background(), userID, "Key B")
		require.NoError(tb, err)
		key2, err := apiKeyService.CreateAPIKey(context.Background(), userID, "Key A")
		require.NoError(tb, err)

		// Test with sort
		sorts := []queryutil.Sort{{Field: "name", Order: queryutil.OrderDesc}}
		filters := []queryutil.CrudFilter{}
		pagination := queryutil.DefaultPagination

		keys, total, err := apiKeyService.GetAPIKeys(context.Background(), userID, filters, sorts, pagination)
		require.NoError(tb, err)
		assert.Equal(tb, int64(2), total)
		assert.Len(tb, keys, 2)
		assert.Equal(tb, key1.UUID, keys[0].UUID) // Key B should come first
		assert.Equal(tb, key2.UUID, keys[1].UUID) // Key A should come second

		// Clean up
		err = apiKeyService.DeleteAPIKey(context.Background(), userID, key1.UUID.ToUUID())
		require.NoError(tb, err)
		err = apiKeyService.DeleteAPIKey(context.Background(), userID, key2.UUID.ToUUID())
		require.NoError(tb, err)
	})
}

func TestAPIKeyService_GetAPIKeys_Pagination(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		apiKeyService := core.GetService[pluginCore.APIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, apiKeyService)

		userID := uint(1)

		// Create keys
		key1, err := apiKeyService.CreateAPIKey(context.Background(), userID, "Key 1")
		require.NoError(tb, err)
		key2, err := apiKeyService.CreateAPIKey(context.Background(), userID, "Key 2")
		require.NoError(tb, err)
		key3, err := apiKeyService.CreateAPIKey(context.Background(), userID, "Key 3")
		require.NoError(tb, err)

		// Test with pagination
		sorts := []queryutil.Sort{{Field: "name", Order: queryutil.OrderAsc}}
		filters := []queryutil.CrudFilter{}

		// Page 1, Limit 2
		pagination, _ := queryutil.CreatePage(1, 2)
		keys, total, err := apiKeyService.GetAPIKeys(context.Background(), userID, filters, sorts, pagination)
		require.NoError(tb, err)
		assert.Equal(tb, int64(3), total)
		assert.Len(tb, keys, 2)
		assert.Equal(tb, key1.UUID, keys[0].UUID)
		assert.Equal(tb, key2.UUID, keys[1].UUID)

		// Page 2, Limit 2
		pagination, _ = queryutil.CreatePage(2, 2)
		keys, total, err = apiKeyService.GetAPIKeys(context.Background(), userID, filters, sorts, pagination)
		require.NoError(tb, err)
		assert.Equal(tb, int64(3), total)
		assert.Len(tb, keys, 1)
		assert.Equal(tb, key3.UUID, keys[0].UUID)

		// Page 3, Limit 2 (empty)
		pagination, _ = queryutil.CreatePage(3, 2)
		keys, total, err = apiKeyService.GetAPIKeys(context.Background(), userID, filters, sorts, pagination)
		require.NoError(tb, err)
		assert.Equal(tb, int64(3), total)
		assert.Len(tb, keys, 0)

		// Clean up
		err = apiKeyService.DeleteAPIKey(context.Background(), userID, key1.UUID.ToUUID())
		require.NoError(tb, err)
		err = apiKeyService.DeleteAPIKey(context.Background(), userID, key2.UUID.ToUUID())
		require.NoError(tb, err)
		err = apiKeyService.DeleteAPIKey(context.Background(), userID, key3.UUID.ToUUID())
		require.NoError(tb, err)
	})
}

func TestAPIKeyService_DeleteAPIKey(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		apiKeyService := core.GetService[pluginCore.APIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, apiKeyService)

		userID1 := uint(1)
		userID2 := uint(2)

		// Create a key for user 1
		key1, err := apiKeyService.CreateAPIKey(context.Background(), userID1, "Key to Delete")
		require.NoError(tb, err)
		require.NotNil(tb, key1)

		// Create a key for user 2 (should not be deleted)
		key2, err := apiKeyService.CreateAPIKey(context.Background(), userID2, "Other User's Key")
		require.NoError(tb, err)
		require.NotNil(tb, key2)

		// Verify key1 exists before deletion
		var fetchedKey pluginDb.APIKey
		result := ctx.DB().First(&fetchedKey, key1.ID)
		require.NoError(tb, result.Error)
		assert.Equal(tb, key1.UUID, fetchedKey.UUID)

		// Test successful deletion by owner
		err = apiKeyService.DeleteAPIKey(context.Background(), userID1, key1.UUID.ToUUID())
		require.NoError(tb, err)

		// Verify key1 is deleted
		result = ctx.DB().First(&fetchedKey, key1.ID)
		assert.ErrorIs(tb, result.Error, gorm.ErrRecordNotFound)

		// Verify key2 still exists
		var fetchedKey2 pluginDb.APIKey
		result = ctx.DB().First(&fetchedKey2, key2.ID)
		require.NoError(tb, result.Error)
		assert.Equal(tb, key2.UUID, fetchedKey2.UUID)

	})
}

func TestAPIKeyService_DeleteAPIKey_NonExistent(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		apiKeyService := core.GetService[pluginCore.APIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, apiKeyService)

		userID := uint(1)

		// Test deleting a non-existent key
		nonExistentUUID := uuid.New()
		err := apiKeyService.DeleteAPIKey(context.Background(), userID, nonExistentUUID)
		assert.ErrorIs(tb, err, gorm.ErrRecordNotFound) // Should return record not found error
	},
	)
}

func TestAPIKeyService_DeleteAPIKey_WrongUser(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		apiKeyService := core.GetService[pluginCore.APIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, apiKeyService)

		userID1 := uint(1)
		userID2 := uint(2)

		// Create a key for user 2
		key2, err := apiKeyService.CreateAPIKey(context.Background(), userID2, "Other User's Key")
		require.NoError(tb, err)
		require.NotNil(tb, key2)

		// Test deleting a key owned by another user
		err = apiKeyService.DeleteAPIKey(context.Background(), userID1, key2.UUID.ToUUID()) // Try deleting key2 with userID1
		assert.ErrorIs(tb, err, gorm.ErrRecordNotFound)                                     // Should return record not found error

		// Verify key2 is still not deleted
		var fetchedKey3 pluginDb.APIKey
		result := ctx.DB().First(&fetchedKey3, key2.ID)
		require.NoError(tb, result.Error)
		assert.Equal(tb, key2.UUID, fetchedKey3.UUID)
	})
}

func TestAPIKeyService_ValidateAPIKey(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		apiKeyService := core.GetService[pluginCore.APIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, apiKeyService)

		userID := uint(1)

		// Create a key
		key, err := apiKeyService.CreateAPIKey(context.Background(), userID, "Key to Validate")
		require.NoError(tb, err)
		require.NotNil(tb, key)

		// Test successful validation
		validatedKey, err := apiKeyService.ValidateAPIKey(context.Background(), userID, key.UUID.ToUUID())
		require.NoError(tb, err)
		assert.NotNil(tb, validatedKey)
		assert.Equal(tb, key.ID, validatedKey.ID)
		assert.Equal(tb, key.UUID, validatedKey.UUID)
		assert.Equal(tb, key.Name, validatedKey.Name)
		assert.Equal(tb, key.UserID, validatedKey.UserID)

	})
}

func TestAPIKeyService_ValidateAPIKey_NonExistent(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		apiKeyService := core.GetService[pluginCore.APIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, apiKeyService)

		userID := uint(1)

		// Test validation of an invalid key
		invalidKeyUUID := uuid.New()
		validatedKey, err := apiKeyService.ValidateAPIKey(context.Background(), userID, invalidKeyUUID)
		require.Error(tb, err)
		require.EqualError(tb, err, "invalid api key") // Check exact error message
		assert.Nil(tb, validatedKey)
	})
}

func TestAPIKeyService_ValidateAPIKey_WrongUser(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		apiKeyService := core.GetService[pluginCore.APIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, apiKeyService)

		userID1 := uint(1)
		userID2 := uint(2)

		// Create a key for user 2
		key, err := apiKeyService.CreateAPIKey(context.Background(), userID2, "Key for User 2")
		require.NoError(tb, err)
		require.NotNil(tb, key)

		// Test validation of a key belonging to a different user
		validatedKey, err := apiKeyService.ValidateAPIKey(context.Background(), userID1, key.UUID.ToUUID())
		require.Error(tb, err)
		require.EqualError(tb, err, "invalid api key") // Check exact error message
		assert.Nil(tb, validatedKey)
	})
}

func TestAPIKeyService_ValidateAPIKey_Expired(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		apiKeyService := core.GetService[pluginCore.APIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, apiKeyService)

		userID := uint(1)

		// Create a key that has already expired
		key, err := apiKeyService.CreateAPIKey(context.Background(), userID, "Expired Key")
		require.NoError(tb, err)
		require.NotNil(tb, key)

		// Set the Expires field to a past time
		pastTime := time.Now().Add(-1 * time.Hour)
		key.Expires = &pastTime
		ctx.DB().Save(key)

		// Test validation of an expired key
		validatedKey, err := apiKeyService.ValidateAPIKey(context.Background(), userID, key.UUID.ToUUID())
		require.Error(tb, err)
		require.EqualError(tb, err, "invalid api key") // Check exact error message
		assert.Nil(tb, validatedKey)
	})
}
