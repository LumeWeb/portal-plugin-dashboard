package api

import (
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

func mapOperationFilters(filters []queryutilFilter.CrudFilter) []queryutilFilter.CrudFilter {
	result := make([]queryutilFilter.CrudFilter, 0, len(filters))
	for _, f := range filters {
		result = append(result, mapOperationFilter(f))
	}
	return result
}

func mapOperationFilter(f queryutilFilter.CrudFilter) queryutilFilter.CrudFilter {
	switch v := f.(type) {
	case *queryutilFilter.LogicalFilter:
		field := v.Field()
		dbField, mapped := operationFieldMappings[field]
		if !mapped {
			return f
		}

		value := v.GetValue()
		if field == "cid" {
			decoded, err := decodeCIDToMultihash(value)
			if err != nil || decoded == nil {
				return f
			}
			return queryutilFilter.NewLogicalFilter(dbField, v.Operator(), decoded)
		}

		return queryutilFilter.NewLogicalFilter(dbField, v.Operator(), value)
	case *queryutilFilter.ConditionalFilter:
		mappedFilters := make([]queryutilFilter.CrudFilter, 0, len(v.Filters))
		for _, nested := range v.Filters {
			mappedFilters = append(mappedFilters, mapOperationFilter(nested))
		}
		return queryutilFilter.NewConditionalFilter(queryutilFilter.LogicalOperator(v.GetOperator()), mappedFilters)
	default:
		return f
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
