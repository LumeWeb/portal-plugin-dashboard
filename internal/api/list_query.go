package api

import (
	"errors"
	"net/http"

	"go.lumeweb.com/queryutil"
	"go.lumeweb.com/queryutil/filter"
	"go.lumeweb.com/queryutil/filter/parser"
	queryutilHttp "go.lumeweb.com/queryutil/http"
	"gorm.io/gorm"
)

// processListQuery validates every client-controlled filter and sort before a
// list service can build SQL. Callers of portal-owned services have no service
// boundary we can change in this plugin, so their HTTP boundary is essential.
func processListQuery[T any, D any](w http.ResponseWriter, r *http.Request, entity string,
	normalize func([]queryutil.CrudFilter, []queryutil.Sort) ([]queryutil.CrudFilter, error),
	service queryutil.EntityFunc[T], convert func(T) D, stringFields ...string,
) error {
	filters, sorts, pagination, err := queryutil.ParseRequestWithOptions(r, parser.WithStringFields(stringFields...))
	if err != nil {
		http.Error(w, "Invalid query parameters", http.StatusBadRequest)
		return err
	}
	filters, err = normalize(filters, sorts)
	if err != nil {
		http.Error(w, "Invalid query parameters", http.StatusBadRequest)
		return err
	}
	items, total, err := service(filters, sorts, pagination)
	if err != nil {
		if errors.Is(err, filter.ErrInvalidQuery) {
			http.Error(w, "Invalid query parameters", http.StatusBadRequest)
		} else if errors.Is(err, gorm.ErrRecordNotFound) {
			http.Error(w, "Entity not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to list "+entity, http.StatusInternalServerError)
		}
		return err
	}
	responses := make([]D, len(items))
	for i, item := range items {
		responses[i] = convert(item)
	}
	queryutilHttp.SetContentRangeHeader(w, entity, pagination, responses, total)
	return queryutilHttp.EncodeJSON(w, queryutil.BuildResponse(responses, total))
}
