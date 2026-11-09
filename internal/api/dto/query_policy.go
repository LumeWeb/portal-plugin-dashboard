// These policies restrict client filters and sorts before queryutil builds SQL.
package dto

import "go.lumeweb.com/queryutil/filter"

func APIKeys() filter.QueryPolicy {
	fields := filter.AllScalarFieldRules("name", "last_used_at", "created_at")
	fields["q"] = filter.FieldRule{Operators: []filter.Operator{filter.OpContains}}
	return filter.QueryPolicy{Fields: fields, SortFields: []string{"name", "last_used_at", "created_at"}}
}

func SocialAccounts() filter.QueryPolicy {
	return filter.QueryPolicy{Fields: filter.AllScalarFieldRules("id", "provider", "provider_user_id", "email", "created_at", "updated_at"), SortFields: []string{"id", "provider", "provider_user_id", "email", "created_at", "updated_at"}}
}

func KeyIdentities() filter.QueryPolicy {
	return filter.QueryPolicy{Fields: filter.AllScalarFieldRules("id", "type", "key", "created_at", "updated_at"), SortFields: []string{"id", "type", "key", "created_at", "updated_at"}}
}

func Operations() filter.QueryPolicy {
	fields := filter.AllScalarFieldRules("id", "operation", "protocol", "status", "status_message", "started_at", "updated_at")
	fields["cid"] = filter.FieldRule{Operators: []filter.Operator{filter.OpEq, filter.OpNe}}
	return filter.QueryPolicy{Fields: fields, SortFields: []string{"id", "operation", "protocol", "status", "status_message", "started_at", "updated_at"}}
}

func SocialProviders() filter.QueryPolicy {
	fields := filter.AllScalarFieldRules("id", "provider_id", "display_name", "client_id", "enabled", "order_index", "created_at", "updated_at")
	return filter.QueryPolicy{Fields: fields, SortFields: []string{"id", "provider_id", "display_name", "client_id", "enabled", "order_index", "created_at", "updated_at"}}
}
