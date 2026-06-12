// Package domain provides pure Go domain models free of persistence annotations.
// These types are the canonical representation for business logic; store.User
// is the persistence layer and should be converted at the boundary.
package domain

import "time"

// User represents a user in the domain. It carries no GORM tags and is
// intentionally decoupled from the persistence schema.
type User struct {
	ID          int64
	Email       string
	Username    string
	DisplayName string
	Status      Status
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Status mirrors store.UserStatus for now; may diverge as domain evolves.
type Status string

const (
	StatusActive   Status = "active"
	StatusInactive Status = "inactive"
	StatusPending  Status = "pending"
)

// TokenPair is the domain representation of an authentication token pair.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	SessionID    string
	ExpiresIn    int64 // seconds
}
