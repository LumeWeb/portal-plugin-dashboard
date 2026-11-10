package dto

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.lumeweb.com/queryutil"
	"go.lumeweb.com/queryutil/filter"
)

func TestListPoliciesRejectUntrustedFieldsAndSorts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		policy    filter.QueryPolicy
		forbidden string
		allowed   string
	}{
		{"api keys", APIKeys(), "user_id", "name"},
		{"social accounts", SocialAccounts(), "user_id", "provider"},
		{"key identities", KeyIdentities(), "user_id", "type"},
		{"operations", Operations(), "user_id", "status"},
		{"admin providers", SocialProviders(), "client_secret", "display_name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, f := range []queryutil.CrudFilter{
				queryutil.NewLogicalFilter(tc.forbidden, filter.OpEq, "1"),
				queryutil.NewConditionalFilter(filter.LogicalOr, []queryutil.CrudFilter{queryutil.NewLogicalFilter(tc.forbidden, filter.OpEq, "1")}),
				queryutil.NewLogicalFilter("id) OR 1=1 --", filter.OpEq, 1),
			} {
				_, err := tc.policy.Normalize([]queryutil.CrudFilter{f}, nil)
				require.ErrorIs(t, err, filter.ErrInvalidQuery)
			}
			_, err := tc.policy.Normalize(nil, []queryutil.Sort{{Field: "(SELECT 1)", Order: filter.OrderAsc}})
			require.ErrorIs(t, err, filter.ErrInvalidQuery)
			_, err = tc.policy.Normalize(nil, []queryutil.Sort{{Field: tc.allowed, Order: filter.SortOrder("asc; SELECT 1")}})
			require.ErrorIs(t, err, filter.ErrInvalidQuery)
			_, err = tc.policy.Normalize([]queryutil.CrudFilter{queryutil.NewLogicalFilter(tc.allowed, filter.OpEq, "x")}, []queryutil.Sort{{Field: tc.allowed, Order: filter.OrderAsc}})
			require.NoError(t, err)
		})
	}
}

func TestAPIKeyNamePolicyMatchesStringParser(t *testing.T) {
	policy := APIKeys()
	for _, item := range []queryutil.CrudFilter{
		queryutil.NewLogicalFilter("name", filter.OpEq, "00123"),
		queryutil.NewLogicalFilter("name", filter.OpIn, []any{"00123", "00456"}),
		queryutil.NewLogicalFilter("name", filter.OpContains, "123"),
	} {
		_, err := policy.Normalize([]queryutil.CrudFilter{item}, nil)
		require.NoError(t, err)
	}
	for _, item := range []queryutil.CrudFilter{
		queryutil.NewLogicalFilter("name", filter.OpGt, 123),
		queryutil.NewLogicalFilter("name", filter.OpBetween, []any{1, 2}),
	} {
		_, err := policy.Normalize([]queryutil.CrudFilter{item}, nil)
		require.ErrorIs(t, err, filter.ErrInvalidQuery)
	}
}

func TestAPIKeysNormalizesNestedLegacySearch(t *testing.T) {
	original := queryutil.NewLogicalFilter("q", filter.OpEq, "00123")
	filters := []queryutil.CrudFilter{queryutil.NewConditionalFilter(filter.LogicalAnd, []queryutil.CrudFilter{original})}
	normalized, err := APIKeys().Normalize(filters, nil)
	require.NoError(t, err)
	leaf := normalized[0].GetFilters()[0]
	require.Equal(t, filter.OpContains, leaf.GetOperator())
	require.Equal(t, "00123", leaf.GetValue())
	require.Equal(t, filter.OpEq, original.Operator())
}

func TestOperationsRejectsUnsupportedCIDOperator(t *testing.T) {
	_, err := Operations().Normalize([]queryutil.CrudFilter{queryutil.NewLogicalFilter("cid", filter.OpContains, "abc")}, nil)
	require.ErrorIs(t, err, filter.ErrInvalidQuery)
}
