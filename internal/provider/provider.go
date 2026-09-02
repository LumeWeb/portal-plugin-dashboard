package provider

// Package-level singleton backing the API layer and plugin metadata.
var providerStore = NewProviderStore()

// Provider returns the shared ProviderStore.
func Provider() *ProviderStore {
	return providerStore
}

// EnabledProviders returns the identifiers of enabled providers.
func EnabledProviders() []string {
	return providerStore.EnabledProviders()
}
