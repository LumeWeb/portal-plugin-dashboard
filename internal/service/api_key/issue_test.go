package api_key

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
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

// TestAPIKeyService_IssueAPIKey_ExpiryWriteFailureRollsBack verifies that
// creating the API key row and persisting its expiry are atomic. It forces the
// expiry write to fail inside IssueAPIKey's transaction and asserts that the
// just-created row is rolled back rather than left behind as an orphan with a
// NULL Expires.
func TestAPIKeyService_IssueAPIKey_ExpiryWriteFailureRollsBack(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		svc := core.GetService[*APIKeyServiceDefault](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, svc)

		// Make the expiry Update step inside IssueAPIKey's transaction fail.
		// Register the hook on the service's own DB instance so it applies to
		// the transaction the service opens internally.
		failExpiry := errors.New("forced expiry write failure")
		err := svc.DB().Callback().Update().Before("gorm:update").
			Register("force_api_key_expiry_failure", func(db *gorm.DB) {
				if db.Statement.Table == "api_keys" {
					_ = db.AddError(failExpiry)
				}
			})
		require.NoError(tb, err)
		tb.Cleanup(func() {
			_ = svc.DB().Callback().Update().Remove("force_api_key_expiry_failure")
		})

		_, issueErr := svc.IssueAPIKey(context.Background(), uint(1), "workspace-1", time.Hour)
		require.Error(tb, issueErr)

		var count int64
		err = ctx.DB().Model(&pluginDb.APIKey{}).Count(&count).Error
		require.NoError(tb, err)
		assert.Zero(tb, count, "no API-key row should remain when the expiry write fails")
	})
}

// counterValue registers the given counter in a fresh registry and returns its
// current value. Used to read package-level metric counters that are not bound
// to a shared registry.
func counterValue(tb coreTesting.TB, c prometheus.Collector) float64 {
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	require.NoError(tb, err)
	if len(mfs) == 0 || len(mfs[0].GetMetric()) == 0 {
		return 0
	}
	return mfs[0].GetMetric()[0].GetCounter().GetValue()
}

// histogramSampleCount registers the given histogram child in a fresh registry
// and returns how many samples it has collected. Used to assert that the issue
// path records duration on the create operation.
func histogramSampleCount(tb coreTesting.TB, observer prometheus.Observer) uint64 {
	reg := prometheus.NewRegistry()
	reg.MustRegister(observer.(prometheus.Collector))
	mfs, err := reg.Gather()
	require.NoError(tb, err)
	if len(mfs) == 0 || len(mfs[0].GetMetric()) == 0 {
		return 0
	}
	return mfs[0].GetMetric()[0].GetHistogram().GetSampleCount()
}

// TestAPIKeyService_IssueAPIKey_CreatePathMetrics verifies that the issue path
// emits the same create-path metrics as CreateAPIKey: it increments the created
// total and records duration on the create operation. Because the metrics are
// package-level and accumulate, each assertion compares against a baseline read
// immediately before the call.
func TestAPIKeyService_IssueAPIKey_CreatePathMetrics(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		svc := core.GetService[*APIKeyServiceDefault](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, svc)

		createdBefore := counterValue(tb, CreatedTotal.WithLabelValues())
		durationBefore := histogramSampleCount(tb, Duration.WithLabelValues(LabelOpCreate))

		issued, err := svc.IssueAPIKey(context.Background(), uint(1), "metrics-workspace", time.Hour)
		require.NoError(tb, err)
		require.NotNil(tb, issued)

		createdAfter := counterValue(tb, CreatedTotal.WithLabelValues())
		assert.Equal(tb, createdBefore+1, createdAfter, "IssueAPIKey should count the created key")

		durationAfter := histogramSampleCount(tb, Duration.WithLabelValues(LabelOpCreate))
		assert.Greater(tb, durationAfter, durationBefore, "IssueAPIKey should record duration on the create operation")
	})
}

// TestAPIKeyService_IssueAPIKey_ErrorPathTracksErrors verifies that when the
// issue path fails, it increments the create error counter and does not count a
// created key.
func TestAPIKeyService_IssueAPIKey_ErrorPathTracksErrors(t *testing.T) {
	coreTesting.RunTestCaseWithDB(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		svc := core.GetService[*APIKeyServiceDefault](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, svc)

		errorsBefore := counterValue(tb, Errors.WithLabelValues(LabelOpCreate))
		createdBefore := counterValue(tb, CreatedTotal.WithLabelValues())

		// Force the expiry Update step inside IssueAPIKey's transaction to fail.
		failExpiry := errors.New("forced expiry write failure")
		err := svc.DB().Callback().Update().Before("gorm:update").
			Register("force_api_key_expiry_failure_metrics", func(db *gorm.DB) {
				if db.Statement.Table == "api_keys" {
					_ = db.AddError(failExpiry)
				}
			})
		require.NoError(tb, err)
		tb.Cleanup(func() {
			_ = svc.DB().Callback().Update().Remove("force_api_key_expiry_failure_metrics")
		})

		_, issueErr := svc.IssueAPIKey(context.Background(), uint(1), "metrics-workspace", time.Hour)
		require.Error(tb, issueErr)

		errorsAfter := counterValue(tb, Errors.WithLabelValues(LabelOpCreate))
		assert.Greater(tb, errorsAfter, errorsBefore, "IssueAPIKey error path should increment the create error counter")

		createdAfter := counterValue(tb, CreatedTotal.WithLabelValues())
		assert.Equal(tb, createdBefore, createdAfter, "IssueAPIKey error path must not count a created key")
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
