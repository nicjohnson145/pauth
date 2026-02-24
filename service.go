package pauth

import (
	"github.com/nicjohnson145/pauth/internal/service"
)

var (
	ErrLoginError            = service.ErrLoginError
	ErrEndpointDisabledError = service.ErrEndpointDisabledError
)

type (
	ServiceConfig = service.ServiceConfig
)

var (
	NewService = service.NewService
)
