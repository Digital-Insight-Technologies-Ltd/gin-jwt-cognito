package models

import "github.com/google/uuid"

type UserContext struct {
	Email          string
	UserID         uuid.UUID `json:"sub"`
	OrganisationID uuid.UUID `json:"custom:organisationId"`
	TenantID       uuid.UUID `json:"custom:tenantId"`
	UserType       string    `json:"userType"`
}
