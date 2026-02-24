package pauth

import (
	"github.com/nicjohnson145/pauth/internal/service"
)

var (
	ErrSessionStoreRequiredError = service.ErrSessionStoreRequiredError
	ErrUnauthenticatedError      = service.ErrUnauthenticatedError
	ErrSessionLookupError        = service.ErrSessionLookupError
	ErrUnauthorizedError         = service.ErrUnauthorizedError
	ErrNoSessionError            = service.ErrNoSessionError
	ErrSessionCastError          = service.ErrSessionCastError
)

type (
	SessionStore   = service.SessionStore
	AuthBypassFunc = service.AuthBypassFunc
)

var (
	SetSessionInContext       = service.SetSessionInContext
	SesssionFromContext       = service.SesssionFromContext
	EnsureSessionHasOneOfRole = service.EnsureSessionHasOneOfRole
)

const (
	RoleAdministrator = service.RoleAdministrator
)
