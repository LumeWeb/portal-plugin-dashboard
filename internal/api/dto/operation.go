package dto

import (
	"time"

	z "github.com/Oudwins/zog"
	"github.com/ipfs/go-cid"
	"go.lumeweb.com/httputil"
	"go.lumeweb.com/portal/db/models"
)

var (
	_ httputil.DTOResponse[*OperationListItem]       = (*OperationListItem)(nil)
	_ httputil.DTOResponse[*OperationDetailResponse] = (*OperationDetailResponse)(nil)
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
	Protocol              string                   `json:"protocol" filter:"true" sort:"true"`
	Status                models.RequestStatusType `json:"status" filter:"true" sort:"true"`
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
	r.Protocol = model.Protocol
	r.Status = model.Status
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
	Protocol              string                   `json:"protocol"`
	Status                models.RequestStatusType `json:"status"`
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
	r.Protocol = model.Protocol
	r.Status = model.Status
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

// WebSocket event structure for operations
type OperationEvent struct {
	Channel string                `json:"channel"`
	Type    string                `json:"type"`
	Payload OperationEventPayload `json:"payload"`
	Date    time.Time             `json:"date"`
}

type OperationEventPayload struct {
	IDs                   []uint64                 `json:"ids"`
	Status                *models.RequestStatusType `json:"status,omitempty"`
	ProgressPercent       *float64                 `json:"progress_percent,omitempty"`
	UpdatedAt             time.Time                `json:"updated_at"`
	StatusMessage         *string                  `json:"status_message,omitempty"`
	EstimatedCompletionAt *time.Time               `json:"estimated_completion_at,omitempty"`
	Error                 *string                  `json:"error,omitempty"`
	CID                   *cid.Cid                 `json:"cid,omitempty"`
	TotalSteps            *int64                   `json:"total_steps,omitempty"`
	CurrentStep           *int64                   `json:"current_step,omitempty"`
}
