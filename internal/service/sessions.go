package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	pbv1beta1connect "github.com/nicjohnson145/pauth/gen/go/pauth/v1beta1/pauthv1beta1connect"
	"github.com/nicjohnson145/pauth/internal/storage"
	"github.com/nicjohnson145/hlp/set"
)

var (
	ErrSessionStoreRequiredError = errors.New("session store required")
	ErrUnauthenticatedError      = errors.New("authentication required")
	ErrSessionLookupError        = errors.New("error retrieving session info")
	ErrUnauthorizedError         = errors.New("unauthorized")
	ErrNoSessionError            = errors.New("no session object in context")
	ErrSessionCastError          = errors.New("unable to cast session value from context")
)

type sessionCtxKeyType struct{}

var (
	sessionCtxKey        sessionCtxKeyType
	pauthPublicEndpoints = set.New(
		pbv1beta1connect.PAuthServiceLoginProcedure,
		pbv1beta1connect.PAuthServicePurgeProcedure,
		pbv1beta1connect.PAuthServiceIsKeyActiveProcedure,
	)
)

type SessionStore interface {
	GetActiveSession(ctx context.Context, sessionKey string) (*storage.Session, error)
	ReadLoginInfo(ctx context.Context, userID *string, email *string) (*storage.LoginInfo, error)
	ListUserRoles(ctx context.Context, userId string) ([]string, error)
}

type AuthBypassFunc func(route string) bool

func intercept(ctx context.Context, bypassFunc AuthBypassFunc, store SessionStore, method string, headers http.Header) (context.Context, error) {
	// If we're told to ignore this route, then let the request go unchanged
	if bypassFunc(method) || pauthPublicEndpoints.Contains(method) {
		return ctx, nil
	}

	// Get the header value
	authKey := headers.Get("Authorization")
	if authKey == "" {
		return nil, ErrUnauthenticatedError
	}

	// Lookup our session in the store
	session, err := store.GetActiveSession(ctx, authKey)
	if err != nil {
		if errors.Is(err, storage.ErrSessionUnknownOrInactiveError) {
			return nil, ErrUnauthorizedError
		}
		return nil, fmt.Errorf("%w: %w", ErrSessionLookupError, err)
	}

	// Set the session object in the context
	return SetSessionInContext(ctx, session), nil
}

func SetSessionInContext(ctx context.Context, session *storage.Session) context.Context {
	return context.WithValue(ctx, sessionCtxKey, session)
}

func SesssionFromContext(ctx context.Context) (*storage.Session, error) {
	val := ctx.Value(sessionCtxKey)
	if val == nil {
		return nil, ErrNoSessionError
	}

	session, ok := val.(*storage.Session)
	if !ok {
		return nil, ErrSessionCastError
	}

	return session, nil
}

func EnsureSessionHasOneOfRole(ctx context.Context, roles ...string) error {
	session, err := SesssionFromContext(ctx)
	if err != nil {
		return err
	}

	if set.New(session.User.Roles...).Intersection(set.New(roles...)).Count() == 0 {
		return ErrUnauthorizedError
	}

	return nil
}
