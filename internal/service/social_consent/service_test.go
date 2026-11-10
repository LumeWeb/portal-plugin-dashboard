package social_consent

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	pluginCore "go.lumeweb.com/portal-plugin-dashboard/core"
	"go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal/core"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func openService(t *testing.T, path string) *SocialConsentServiceDefault {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(path+"?_busy_timeout=5000&_journal_mode=WAL"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	require.NoError(t, db.AutoMigrate(&models.SocialConsent{}))
	svc := &SocialConsentServiceDefault{BaseComponent: &core.BaseComponent{}}
	svc.SetDB(db)
	return svc
}

func TestConsent_OnlyOneInstanceCanConsumeNonce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "consents.db")
	first, second := openService(t, path), openService(t, path)
	ctx := context.Background()
	deadline := time.Now().Add(time.Minute)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	start := make(chan struct{})
	for _, svc := range []*SocialConsentServiceDefault{first, second} {
		wg.Go(func() { <-start; results <- svc.Consume(ctx, "one-time-consent", deadline) })
	}
	close(start)
	wg.Wait()
	close(results)
	successes, rejections := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, pluginCore.ErrInvalidConsent) {
			rejections++
		} else {
			t.Fatal(err)
		}
	}
	require.Equal(t, 1, successes)
	require.Equal(t, 1, rejections)
	reopened := openService(t, path)
	require.ErrorIs(t, reopened.Consume(ctx, "one-time-consent", deadline), pluginCore.ErrInvalidConsent)
}

func TestConsent_ExpiredOrEmptyNonceCannotBeConsumed(t *testing.T) {
	svc := openService(t, filepath.Join(t.TempDir(), "consents.db"))
	for _, tc := range []struct {
		token    string
		deadline time.Time
	}{
		{token: "expired", deadline: time.Now().Add(-time.Second)},
		{token: "", deadline: time.Now().Add(time.Minute)},
	} {
		require.ErrorIs(t, svc.Consume(context.Background(), tc.token, tc.deadline), pluginCore.ErrInvalidConsent)
	}
}

func TestConsent_DatabaseFailureDoesNotConsumeNonce(t *testing.T) {
	svc := &SocialConsentServiceDefault{BaseComponent: &core.BaseComponent{}}
	require.Error(t, svc.Consume(context.Background(), "one-time-consent", time.Now().Add(time.Minute)))
}
