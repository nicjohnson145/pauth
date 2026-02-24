package pauth

import (
	"github.com/nicjohnson145/pauth/internal/storage"
)

var (
	ErrUserAlreadyExistsError        = storage.ErrUserAlreadyExistsError
	ErrUnknownUserError              = storage.ErrUnknownUserError
	ErrIncorrectPasswordError        = storage.ErrIncorrectPasswordError
	ErrNoPasswordConfiguredError     = storage.ErrNoPasswordConfiguredError
	ErrSessionUnknownOrInactiveError = storage.ErrSessionUnknownOrInactiveError

	ErrInvalidConfigurationError = storage.ErrInvalidConfigurationError
	ErrNoHostError               = storage.ErrNoHostError
	ErrNoDBNameError             = storage.ErrNoDBNameError
	ErrNoUserError               = storage.ErrNoUserError
	ErrNoPasswordError           = storage.ErrNoPasswordError
)

type (
	Storer                      = storage.Storer
	PostgresStoreConnectionOpts = storage.PostgresStoreConnectionOpts
	PostgresStoreOpts           = storage.PostgresStoreOpts
	MemoryStoreOpts             = storage.MemoryStoreOpts
)

var (
	NewPostgresStore = storage.NewPostgresStore
	NewMemoryStore   = storage.NewMemoryStore
)
