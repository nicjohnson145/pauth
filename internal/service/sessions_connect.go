package service

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
)

type ConnectInterceptorConfig struct {
	Store      SessionStore
	BypassFunc AuthBypassFunc
}

func NewConnectInterceptor(conf ConnectInterceptorConfig) (connect.Interceptor, error) {
	bypass := conf.BypassFunc
	if bypass == nil {
		bypass = func(route string) bool {
			return false
		}
	}

	if conf.Store == nil {
		return nil, ErrSessionStoreRequiredError
	}

	return &connectInterceptor{
		bypassFunc: bypass,
		store:      conf.Store,
	}, nil
}

type connectInterceptor struct {
	store      SessionStore
	bypassFunc AuthBypassFunc
}

func (c *connectInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		newCtx, err := c.intercept(ctx, req.Spec().Procedure, req.Header())
		if err != nil {
			return nil, err
		}
		return next(newCtx, req)
	})
}

func (c *connectInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return connect.StreamingHandlerFunc(func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		newCtx, err := c.intercept(ctx, conn.Spec().Procedure, conn.RequestHeader())
		if err != nil {
			return err
		}
		return next(newCtx, conn)
	})
}

func (c *connectInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return connect.StreamingClientFunc(func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		return next(ctx, spec)
	})
}

func (c *connectInterceptor) intercept(ctx context.Context, method string, headers http.Header) (context.Context, error) {
	return intercept(ctx, c.bypassFunc, c.store, method, headers)
}
