package pauth

import (
	"github.com/nicjohnson145/pauth/internal/service"
)

type (
	ConnectInterceptorConfig = service.ConnectInterceptorConfig
)

var (
	NewConnectInterceptor = service.NewConnectInterceptor
	BasicAuthMiddleware   = service.BasicAuthMiddleware
)
