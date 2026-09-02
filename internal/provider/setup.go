package provider

import (
	"fmt"
	"net/url"
	"sort"
	"sync"
	"time"

	"go.lumeweb.com/portal-plugin-dashboard/internal"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal/core"
	"gorm.io/gorm"
)

// reloadCooldown throttles how often a cache miss may trigger a DB reload. The
// unauthenticated login endpoints drive lookups with caller-supplied provider
// names, so without a window a burst of misses would amplify into one
// full-table SELECT per request.
const reloadCooldown = 2 * time.Second

// PublicProviderInfo is the public metadata exposed for an enabled provider.
type PublicProviderInfo struct {
	ProviderID  string `json:"provider_id"`
	DisplayName string `json:"display_name"`
	OrderIndex  int    `json:"order_index"`
}

// ProviderStore holds the OAuthProvider instances for enabled providers,
// built from SocialProviderConfig rows in the database. It is refreshed at
// startup and after every admin CRUD mutation, and self-heals on a lookup
// miss so a failed cache reload never leaves login reading stale providers.
type ProviderStore struct {
	mu         sync.RWMutex
	providers  map[string]OAuthProvider
	ctx        core.Context
	db         *gorm.DB
	lastReload time.Time // last DB reload attempt, for the miss throttle
	reloadMu   sync.Mutex // serializes reloads so concurrent misses share one
}

// NewProviderStore creates an empty ProviderStore.
func NewProviderStore() *ProviderStore {
	return &ProviderStore{
		providers: make(map[string]OAuthProvider),
	}
}

// SetContext stores the core context used to compute the callback URL.
func (s *ProviderStore) SetContext(ctx core.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctx = ctx
}

// LoadFromDB rebuilds the in-memory provider set from the enabled provider
// rows in the database.
func (s *ProviderStore) LoadFromDB(db *gorm.DB) error {
	var configs []pluginDb.SocialProviderConfig
	if err := db.Where("enabled = ?", true).Find(&configs).Error; err != nil {
		return fmt.Errorf("load enabled social providers: %w", err)
	}

	providers := make(map[string]OAuthProvider, len(configs))
	for i := range configs {
		cfg := &configs[i]
		providers[cfg.ProviderID] = newGenericFromConfig(cfg, s.callbackURL(cfg.ProviderID))
	}

	s.mu.Lock()
	s.providers = providers
	s.db = db
	s.mu.Unlock()
	return nil
}

// GetProvider returns the OAuthProvider for a provider identifier. On a miss it
// falls back to a single-flight, throttled DB reload to self-heal: an admin
// mutation whose cache reload failed (or a provider enabled elsewhere) is
// picked up here without a process restart, while a burst of misses can only
// trigger one reload per cooldown window rather than one DB read per request.
func (s *ProviderStore) GetProvider(name string) (OAuthProvider, error) {
	s.mu.RLock()
	p, ok := s.providers[name]
	db := s.db
	s.mu.RUnlock()
	if ok {
		return p, nil
	}
	if db == nil {
		return nil, fmt.Errorf("provider %s not enabled", name)
	}

	if s.reloadIfDue(db) {
		s.mu.RLock()
		p, ok = s.providers[name]
		s.mu.RUnlock()
		if ok {
			return p, nil
		}
	}

	return nil, fmt.Errorf("provider %s not enabled", name)
}

// reloadIfDue performs a DB reload only when the cooldown window has elapsed.
// reloadIfDue is the only reader/writer of lastReload, so reloadMu both
// serializes concurrent callers (one reload serves them all — single-flight)
// and guards the throttle field. Holding the lock across the check and the
// reload keeps the whole section atomic. Both success and failure advance
// lastReload so a flaky DB is not hammered on every subsequent request.
func (s *ProviderStore) reloadIfDue(db *gorm.DB) bool {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	if time.Since(s.lastReload) < reloadCooldown {
		return false
	}

	err := s.LoadFromDB(db)
	s.lastReload = time.Now()
	return err == nil
}

// EvictProvider removes a provider from the in-memory provider set regardless
// of DB state. Callers use it after a delete/disable whose cache reload failed,
// so a provider whose DB row is gone or disabled is never served on a cache
// hit; the next lookup goes through the throttled miss reload instead.
//
// It holds reloadMu so it is serialized against reloadIfDue's single-flight
// reload: an in-flight reload that read a pre-delete/pre-disable DB snapshot
// cannot re-add the provider to the map after this eviction removes it.
func (s *ProviderStore) EvictProvider(name string) {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.providers, name)
}

// EnabledProviders returns the list of enabled provider identifiers.
func (s *ProviderStore) EnabledProviders() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.providers))
	for name := range s.providers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ListPublicProviders returns public metadata for all enabled providers,
// sorted by OrderIndex then ProviderID.
func (s *ProviderStore) ListPublicProviders() []PublicProviderInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	infos := make([]PublicProviderInfo, 0, len(s.providers))
	for name := range s.providers {
		infos = append(infos, PublicProviderInfo{ProviderID: name})
	}
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].ProviderID < infos[j].ProviderID
	})
	return infos
}

func (s *ProviderStore) callbackURL(providerID string) string {
	if s.ctx == nil {
		return ""
	}

	httpSvc, ok := s.ctx.Service(core.HTTP_SERVICE).(core.HTTPService)
	if !ok {
		return ""
	}

	base := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)
	u := url.URL{Path: "/api/account/auth/sso/" + providerID + "/callback"}
	return base + u.Path
}

func newGenericFromConfig(cfg *pluginDb.SocialProviderConfig, callbackURL string) OAuthProvider {
	p := NewGenericOAuth2Provider(
		cfg.ProviderID,
		cfg.ClientID, cfg.ClientSecret,
		cfg.GetScopes(),
		cfg.AuthURL, cfg.TokenURL, cfg.UserURL, callbackURL,
		cfg.UserEmailKey, cfg.UserIDKey, cfg.UserNameKey,
	)
	p.displayName = cfg.DisplayName
	return p
}
