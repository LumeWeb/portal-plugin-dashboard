package api

import (
	"fmt"

	"github.com/ipfs/go-cid"
	queryutilFilter "go.lumeweb.com/queryutil/filter"
)

var operationFieldMappings = map[string]string{
	"id":             "id",
	"operation":      "operation",
	"protocol":       "protocol",
	"status":         "status",
	"status_message": "status_message",
	"started_at":     "created_at",
	"updated_at":     "updated_at",
	"cid":            "hash",
}

func mapOperationFilters(filters []queryutilFilter.CrudFilter) ([]queryutilFilter.CrudFilter, error) {
	result := make([]queryutilFilter.CrudFilter, 0, len(filters))
	for _, f := range filters {
		mapped, err := mapOperationFilter(f)
		if err != nil {
			return nil, err
		}
		result = append(result, mapped)
	}
	return result, nil
}

func mapOperationFilter(f queryutilFilter.CrudFilter) (queryutilFilter.CrudFilter, error) {
	switch v := f.(type) {
	case *queryutilFilter.LogicalFilter:
		field := v.Field()
		dbField, mapped := operationFieldMappings[field]
		if !mapped {
			return f, nil
		}

		value := v.GetValue()
		if field == "cid" {
			decoded, err := decodeCIDToMultihash(value)
			if err != nil {
				return nil, fmt.Errorf("invalid cid filter value: %w", err)
			}
			if decoded == nil {
				return nil, fmt.Errorf("cid filter requires a string value, got %T", value)
			}
			return queryutilFilter.NewLogicalFilter(dbField, v.Operator(), decoded), nil
		}

		return queryutilFilter.NewLogicalFilter(dbField, v.Operator(), value), nil
	case *queryutilFilter.ConditionalFilter:
		mappedFilters := make([]queryutilFilter.CrudFilter, 0, len(v.Filters))
		for _, nested := range v.Filters {
			mapped, err := mapOperationFilter(nested)
			if err != nil {
				return nil, err
			}
			mappedFilters = append(mappedFilters, mapped)
		}
		return queryutilFilter.NewConditionalFilter(queryutilFilter.LogicalOperator(v.GetOperator()), mappedFilters), nil
	default:
		return f, nil
	}
}

func mapOperationSorts(sorts []queryutilFilter.Sort) []queryutilFilter.Sort {
	result := make([]queryutilFilter.Sort, 0, len(sorts))
	for _, s := range sorts {
		dbField, mapped := operationFieldMappings[s.Field]
		if !mapped {
			result = append(result, s)
			continue
		}
		result = append(result, queryutilFilter.Sort{
			Field: dbField,
			Order: s.Order,
		})
	}
	return result
}

func decodeCIDToMultihash(value any) ([]byte, error) {
	cidStr, ok := value.(string)
	if !ok {
		return nil, nil
	}

	decoded, err := cid.Decode(cidStr)
	if err != nil {
		return nil, err
	}

	return decoded.Hash(), nil
}
