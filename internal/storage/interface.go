package storage

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/go-logr/logr"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/nicjohnson145/hlp"
	hsqlx "github.com/nicjohnson145/hlp/sqlx"
	pbv1beta1 "github.com/nicjohnson145/pauth/gen/go/pauth/v1beta1"
)

//go:embed postgres-migrations/*.sql
var postgresMigrationFS embed.FS

const (
	migrationsTable = "pauth_migrations"
)

var (
	ErrUserAlreadyExistsError        = errors.New("a user with this id already exists")
	ErrUnknownUserError              = errors.New("unknown user")
	ErrIncorrectPasswordError        = errors.New("password does not match")
	ErrNoPasswordConfiguredError     = errors.New("no password configured")
	ErrSessionUnknownOrInactiveError = errors.New("session unknwon or inactive")

	ErrInvalidConfigurationError = errors.New("invalid configuration")
	ErrNoHostError               = fmt.Errorf("%w: no host given", ErrIncorrectPasswordError)
	ErrNoDBNameError             = fmt.Errorf("%w: no dbname given", ErrInvalidConfigurationError)
	ErrNoUserError               = fmt.Errorf("%w: no user given", ErrInvalidConfigurationError)
	ErrNoPasswordError           = fmt.Errorf("%w: no password given", ErrInvalidConfigurationError)
)

type CreateUserRequest struct {
	User           *pbv1beta1.User
	HashedPassword *string
}

type SetUserPasswordRequest struct {
	UserId         string
	HashedPassword string
}

type CreateSessionRequest struct {
	Session     *Session
	ActiveUntil time.Time
}

type LoginInfo struct {
	User           *pbv1beta1.User
	StoredPassword string
}

type Storer interface {
	Purge(ctx context.Context) error

	CreateUser(ctx context.Context, req *CreateUserRequest) error
	ReadUser(ctx context.Context, userId string) (*pbv1beta1.User, error)
	ReadLoginInfo(ctx context.Context, userID *string, email *string) (*LoginInfo, error)
	ListUsers(ctx context.Context, req *pbv1beta1.ListUsersRequest) ([]*pbv1beta1.User, error)
	SetUserPassword(ctx context.Context, req *SetUserPasswordRequest) error
	UpdateUser(ctx context.Context, user *pbv1beta1.User) error
	DeleteUser(ctx context.Context, req *pbv1beta1.DeleteUserRequest) error
	ListUserRoles(ctx context.Context, userId string) ([]string, error)
	GrantUserRoles(ctx context.Context, req *pbv1beta1.GrantUserRoleRequest) error
	RevokeUserRoles(ctx context.Context, req *pbv1beta1.RevokeUserRoleRequest) error

	GetActiveSession(ctx context.Context, sessionKey string) (*Session, error)
	CreateSession(ctx context.Context, req *CreateSessionRequest) error
	RemoveSession(ctx context.Context, sessionKey string) error
}

func goMigrateMigration(sourceFS fs.FS, driver database.Driver, dbName string) func() error {
	return func() error {
		source, err := iofs.New(sourceFS, ".")
		if err != nil {
			return fmt.Errorf("error creating migration source: %w", err)
		}

		migrater, err := migrate.NewWithInstance("iofs", source, dbName, driver)
		if err != nil {
			return fmt.Errorf("error creating migration instance: %w", err)
		}

		if err := migrater.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			return fmt.Errorf("error executing migrations: %w", err)
		}

		return nil
	}
}

type PostgresStoreConnectionOpts struct {
	Host     string
	Port     int
	DBName   string
	User     string
	Password string //nolint: gosec // its env config, relax
	SSLMode  string
}

type PostgresStoreOpts struct {
	Logger *logr.Logger
	// DB is an existing database handle. Either DB or ConnectionOpts is required
	DB *sql.DB
	// ConnectionOpts is a set of params to connect to a postgres database. Either DB or ConnectionOpts is required
	ConnectionOpts *PostgresStoreConnectionOpts
	// NowFunc optionally overrides "now" for the storage layer. Exposed only for unit tests
	NowFunc func() time.Time
}

func NewPostgresStore(opts PostgresStoreOpts) (Storer, func(), error) {
	cleanup := func() {}

	// User must specify one or the other
	if opts.DB == nil && opts.ConnectionOpts == nil {
		return nil, cleanup, fmt.Errorf("%w: no DB or connection params given", ErrInvalidConfigurationError)
	}

	// Use the provided DB, or connect via the params, if we're given a DB, assume the caller will close it for us
	db := opts.DB
	if db == nil {
		host := opts.ConnectionOpts.Host
		if host == "" {
			return nil, cleanup, ErrNoHostError
		}

		port := opts.ConnectionOpts.Port
		if port == 0 {
			port = 5432
		}

		dbname := opts.ConnectionOpts.DBName
		if dbname == "" {
			return nil, cleanup, ErrNoDBNameError
		}

		user := opts.ConnectionOpts.User
		if user == "" {
			return nil, cleanup, ErrNoUserError
		}

		password := opts.ConnectionOpts.Password
		if password == "" {
			return nil, cleanup, ErrNoPasswordError
		}

		sslMode := opts.ConnectionOpts.SSLMode
		if sslMode == "" {
			sslMode = "prefer"
		}

		d, err := sql.Open(
			"postgres",
			fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s", user, password, host, port, dbname, sslMode),
		)
		if err != nil {
			return nil, cleanup, fmt.Errorf("error opening DB: %w", err)
		}
		db = d

		cleanup = func() {
			_ = db.Close()
		}
	}

	logOut := func(str string) {}
	if opts.Logger != nil {
		logOut = func(str string) {
			opts.Logger.Info(str)
		}
	}

	logOut("waiting for DB to show connectable")

	// TODO: should these be config driven? maybe.
	waitOpts := hsqlx.DBWaitOpts{
		Timeout: hlp.Ptr(5 * time.Second),
		Logger:  opts.Logger,
	}
	if err := hsqlx.WaitForDBConnectable(db, waitOpts); err != nil {
		return nil, cleanup, err
	}

	logOut("executing migrations")
	if err := PreparePostgresDB(db); err != nil {
		return nil, cleanup, err
	}

	return NewPostgres(PostgresConfig{
		DB:      db,
		NowFunc: opts.NowFunc,
	}), cleanup, nil
}

type MemoryStoreOpts struct {
	// NowFunc optionally overrides "now" for the storage layer. Exposed only for unit tests
	NowFunc func() time.Time
}

func NewMemoryStore(opts MemoryStoreOpts) (Storer, func(), error) {
	return NewMemory(MemoryConfig{
		Now: opts.NowFunc,
	}), func() {}, nil
}
