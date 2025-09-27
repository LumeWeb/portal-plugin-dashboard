package dto

import (
	"time"

	z "github.com/Oudwins/zog"
	"github.com/ipfs/go-cid"
	"github.com/samber/lo"
	"go.lumeweb.com/httputil"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/portal/db/models"
)

var (
	_ httputil.DTOResponse[*OperationListItem]       = (*OperationListItem)(nil)
	_ httputil.DTOResponse[*OperationDetailResponse] = (*OperationDetailResponse)(nil)
	_ httputil.DTOResponse[map[string][]string]      = (*OperationFiltersResponse)(nil)
)

type OperationRequest struct {
	ID uint64 `param:"id" zog:"required"`
}

func (r *OperationRequest) Schema() *z.StructSchema {
	return z.Struct(z.Shape{
		"ID": z.UintLike[uint64]().Required(),
	})
}

func (r *OperationRequest) ToModel() (*OperationRequest, error) {
	return r, nil
}

type OperationListItem struct {
	ID                    uint64                   `json:"id" filter:"true" sort:"true"`
	Operation             string                   `json:"operation" filter:"true" sort:"true"`
	OperationDisplayName  string                   `json:"operation_display_name"`
	Protocol              string                   `json:"protocol" filter:"true" sort:"true"`
	ProtocolDisplayName   string                   `json:"protocol_display_name"`
	Status                models.RequestStatusType `json:"status" filter:"true" sort:"true"`
	StatusDisplayName     string                   `json:"status_display_name"`
	StatusMessage         string                   `json:"status_message" filter:"true" sort:"true"`
	ProgressPercent       float64                  `json:"progress_percent" filter:"true" sort:"true"`
	StartedAt             time.Time                `json:"started_at" filter:"true" sort:"true"`
	UpdatedAt             time.Time                `json:"updated_at" filter:"true" sort:"true"`
	EstimatedCompletionAt *time.Time               `json:"estimated_completion_at,omitempty" filter:"true" sort:"true"`
	CID                   *cid.Cid                 `json:"cid,omitempty" filter:"true" sort:"true"`
	TotalSteps            *int64                   `json:"total_steps,omitempty" filter:"true" sort:"true"`
	CurrentStep           *int64                   `json:"current_step,omitempty" filter:"true" sort:"true"`
	Error                 *string                  `json:"error,omitempty" filter:"true" sort:"true"`
}

func (r *OperationListItem) FromModel(model *OperationListItem) error {
	r.ID = model.ID
	r.Operation = model.Operation
	r.OperationDisplayName = model.OperationDisplayName
	r.Protocol = model.Protocol
	r.ProtocolDisplayName = model.ProtocolDisplayName
	r.Status = model.Status
	r.StatusDisplayName = model.StatusDisplayName
	r.StatusMessage = model.StatusMessage
	r.ProgressPercent = model.ProgressPercent
	r.StartedAt = model.StartedAt
	r.UpdatedAt = model.UpdatedAt
	r.EstimatedCompletionAt = model.EstimatedCompletionAt
	r.CID = model.CID
	r.TotalSteps = model.TotalSteps
	r.CurrentStep = model.CurrentStep
	r.Error = model.Error
	return nil
}

type OperationDetailResponse struct {
	ID                    uint64                   `json:"id"`
	Operation             string                   `json:"operation"`
	OperationDisplayName  string                   `json:"operation_display_name"`
	Protocol              string                   `json:"protocol"`
	ProtocolDisplayName   string                   `json:"protocol_display_name"`
	Status                models.RequestStatusType `json:"status"`
	StatusDisplayName     string                   `json:"status_display_name"`
	StatusMessage         string                   `json:"status_message"`
	ProgressPercent       float64                  `json:"progress_percent"`
	StartedAt             time.Time                `json:"started_at"`
	UpdatedAt             time.Time                `json:"updated_at"`
	EstimatedCompletionAt *time.Time               `json:"estimated_completion_at,omitempty"`
	CID                   *cid.Cid                 `json:"cid,omitempty"`
	TotalSteps            *int64                   `json:"total_steps,omitempty"`
	CurrentStep           *int64                   `json:"current_step,omitempty"`
	Error                 *string                  `json:"error,omitempty"`
}

func (r *OperationDetailResponse) FromModel(model *OperationDetailResponse) error {
	r.ID = model.ID
	r.Operation = model.Operation
	r.OperationDisplayName = model.OperationDisplayName
	r.Protocol = model.Protocol
	r.ProtocolDisplayName = model.ProtocolDisplayName
	r.Status = model.Status
	r.StatusDisplayName = model.StatusDisplayName
	r.StatusMessage = model.StatusMessage
	r.ProgressPercent = model.ProgressPercent
	r.StartedAt = model.StartedAt
	r.UpdatedAt = model.UpdatedAt
	r.EstimatedCompletionAt = model.EstimatedCompletionAt
	r.Error = model.Error
	r.CID = model.CID
	r.TotalSteps = model.TotalSteps
	r.CurrentStep = model.CurrentStep
	return nil
}

type OperationFiltersResponse struct {
	Data OperationFiltersResponseData `json:"data"`
}

type OperationFiltersResponseData struct {
	Statuses   []OperationFilterItem `json:"statuses"`
	Operations []OperationFilterItem `json:"operations"`
	Protocols  []OperationFilterItem `json:"protocols"`
}

func (r *OperationFiltersResponse) FromModel(_ map[string][]string) error {
	return nil
}

func GetOperationDisplayNames(finder core.OperationFinder, operationStrings []string) []OperationFilterItem {
	return lo.Map(operationStrings, func(operation string, i int) OperationFilterItem {
		handler, _, err := finder.FindOperationHandler(operation)
		if err != nil {
			// If we can't find the handler, use the operation string as the display name
			return OperationFilterItem{
				Value: operation,
				Name:  operation,
			}
		}
		name := core.GetOperationDisplayName(handler)

		return OperationFilterItem{
			Value: operation,
			Name:  name,
		}
	})
}

func GetProtocolDisplayNames(protocolStrings []string) []OperationFilterItem {
	// Get all registered protocols and create a map of names to display names
	protocolList := core.GetProtocolList()
	protocolDisplayMap := make(map[string]string)
	for _, protocol := range protocolList {
		protocolDisplayMap[protocol.Name()] = protocol.DisplayName()
	}

	return lo.Map(protocolStrings, func(protocol string, i int) OperationFilterItem {
		name := protocol

		// Check if we have a display name for this protocol
		if displayName, exists := protocolDisplayMap[protocol]; exists {
			name = displayName
		}

		return OperationFilterItem{
			Value: protocol,
			Name:  name,
		}
	})
}

func GetStatusDisplayNames(statusStrings []string) []OperationFilterItem {
	return lo.Map(statusStrings, func(status string, i int) OperationFilterItem {
		name := status

		// Try to parse as models.RequestStatusType
		statusType := models.RequestStatusType(status)
		if displayInfo, exists := core.GetRequestStatusDisplayInfo(statusType); exists {
			name = displayInfo.Name
		}

		return OperationFilterItem{
			Value: status,
			Name:  name,
		}
	})
}

type OperationFilterItem struct {
	Value string `json:"value"`
	Name  string `json:"name"`
}

// WebSocket event structure for operations
type OperationEvent struct {
	Channel string                `json:"channel"`
	Type    string                `json:"type"`
	Payload OperationEventPayload `json:"payload"`
	Date    time.Time             `json:"date"`
}

type OperationEventPayload struct {
	IDs                   []uint64                  `json:"ids"`
	Status                *models.RequestStatusType `json:"status,omitempty"`
	ProgressPercent       *float64                  `json:"progress_percent,omitempty"`
	UpdatedAt             time.Time                 `json:"updated_at"`
	StatusMessage         *string                   `json:"status_message,omitempty"`
	EstimatedCompletionAt *time.Time                `json:"estimated_completion_at,omitempty"`
	Error                 *string                   `json:"error,omitempty"`
	CID                   *cid.Cid                  `json:"cid,omitempty"`
	TotalSteps            *int64                    `json:"total_steps,omitempty"`
	CurrentStep           *int64                    `json:"current_step,omitempty"`
}
