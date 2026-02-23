package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/jmoiron/sqlx"
	"github.com/nicjohnson145/hlp"
	hsqlx "github.com/nicjohnson145/hlp/sqlx"
	pbv1beta1 "github.com/nicjohnson145/pauth/gen/go/pauth/v1beta1"
)

func PreparePostgresDB(db *sql.DB) error {
	driver, err := postgres.WithInstance(db, &postgres.Config{MigrationsTable: migrationsTable})
	if err != nil {
		return fmt.Errorf("error creating driver: %w", err)
	}
	subFS, err := fs.Sub(postgresMigrationFS, "postgres-migrations")
	if err != nil {
		return fmt.Errorf("error creating sub fs: %w", err)
	}

	if err := goMigrateMigration(subFS, driver, "postgres")(); err != nil {
		return fmt.Errorf("error migrating: %w", err)
	}

	return nil
}

type PostgresConfig struct {
	DB      *sql.DB
	NowFunc func() time.Time
}

func NewPostgres(conf PostgresConfig) *Postgres {
	now := conf.NowFunc
	if now == nil {
		now = func() time.Time {
			return time.Now().UTC()
		}
	}
	return &Postgres{
		db:  sqlx.NewDb(conf.DB, "postgres"),
		now: now,
	}
}

type Postgres struct {
	db  *sqlx.DB
	now func() time.Time
}

func (p *Postgres) Purge(ctx context.Context) error {
	tables := []string{
		"pauth_user",
		"pauth_user_role",
		"pauth_user_session",
	}
	return hsqlx.WithTransaction(p.db, func(txn *sqlx.Tx) error {
		for _, table := range tables {
			if _, err := txn.ExecContext(ctx, fmt.Sprintf("DELETE FROM %v", table)); err != nil {
				return fmt.Errorf("error deleting: %w", err)
			}
		}
		return nil
	})
}

func (p *Postgres) CreateUser(ctx context.Context, req *CreateUserRequest) error {
	return hsqlx.WithTransaction(p.db, func(txn *sqlx.Tx) error {
		if err := p.writeUser(ctx, txn, req.User); err != nil {
			return fmt.Errorf("error writing user: %w", err)
		}
		if req.HashedPassword != nil {
			if err := p.setUserPassword(ctx, txn, req.User.Id, *req.HashedPassword); err != nil {
				return fmt.Errorf("error setting password: %w", err)
			}
		}

		return nil
	})
}

func (p *Postgres) writeUser(ctx context.Context, txn sqlx.ExtContext, usr *pbv1beta1.User) error {
	stmt := `
		INSERT INTO
			pauth_user
			(
				id,
				email,
				full_name
			)
		VALUES
			(
				:id,
				:email,
				:full_name
			)
		ON CONFLICT ON CONSTRAINT
			pauth_user_pk
		DO
			UPDATE
		SET
			email = EXCLUDED.email,
			full_name = EXCLUDED.full_name
	`
	if _, err := sqlx.NamedExecContext(ctx, txn, stmt, PBUserToDBUser(usr)); err != nil {
		return fmt.Errorf("error inserting: %w", err)
	}

	return nil
}

func (p *Postgres) setUserPassword(ctx context.Context, txn sqlx.ExtContext, id string, password string) error {
	stmt := `
		UPDATE
			pauth_user
		SET
			password = :password
		WHERE
			id = :user_id
	`
	args := map[string]any{
		"password": password,
		"user_id":  id,
	}

	result, err := sqlx.NamedExecContext(ctx, txn, stmt, args)
	if err != nil {
		return fmt.Errorf("error updating: %w", err)
	}

	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting affected row count: %w", err)
	}

	if count != 1 {
		return ErrUnknownUserError
	}

	return nil
}

func (p *Postgres) ReadUser(ctx context.Context, userId string) (*pbv1beta1.User, error) {
	stmt := `
		WITH agged_user_roles AS (
			SELECT
				user_id,
				ARRAY_AGG(role) AS roles
			FROM
				pauth_user_role
			GROUP BY
				user_id
		)
		SELECT
			u.id,
			u.email,
			u.full_name,
			aur.roles
		FROM
			pauth_user AS u
		LEFT OUTER JOIN
			agged_user_roles AS aur
		ON
			u.id = aur.user_id
		WHERE
			u.id = :user_id
	`
	args := map[string]any{
		"user_id": userId,
	}

	rows, err := hsqlx.RequireExactSelectNamedCtx[DBOutputUser](ctx, 1, p.db, stmt, args)
	if err != nil {
		if errors.Is(err, hsqlx.ErrNotFoundError) {
			return nil, ErrUnknownUserError
		}
		return nil, fmt.Errorf("error selecting: %w", err)
	}

	return DBOutputUserToPBUser(rows[0]), nil
}

func (p *Postgres) ReadLoginInfo(ctx context.Context, userID *string, email *string) (*LoginInfo, error) {
	// TODO: probably should use a query builder here
	var condition string
	var args map[string]any
	switch true {
	case userID != nil:
		condition = "u.id = :user_id"
		args = map[string]any{
			"user_id": userID,
		}
	case email != nil:
		condition = "u.email = :email"
		args = map[string]any{
			"email": email,
		}
	default:
		return nil, fmt.Errorf("unsupported search configuration")
	}

	stmt := fmt.Sprintf(`
		WITH agged_user_roles AS (
			SELECT
				user_id,
				ARRAY_AGG(role) AS roles
			FROM
				pauth_user_role
			GROUP BY
				user_id
		)
		SELECT
			u.*,
			aur.roles
		FROM
			pauth_user AS u
		LEFT OUTER JOIN
			agged_user_roles AS aur
		ON
			u.id = aur.user_id
		WHERE
			%v
	`, condition)

	rows, err := hsqlx.RequireExactSelectNamedCtx[DBOutputUserWithPassword](ctx, 1, p.db, stmt, args)
	if err != nil {
		if errors.Is(err, hsqlx.ErrNotFoundError) {
			return nil, ErrUnknownUserError
		}
		return nil, fmt.Errorf("error selecting: %w", err)
	}

	return DBOutputUserWithPasswordToLoginInfo(rows[0]), nil
}

func (p *Postgres) ListUsers(ctx context.Context, req *pbv1beta1.ListUsersRequest) ([]*pbv1beta1.User, error) {
	stmt := `
		WITH agged_user_roles AS (
			SELECT
				user_id,
				ARRAY_AGG(role) AS roles
			FROM
				pauth_user_role
			GROUP BY
				user_id
		)
		SELECT
			u.id,
			u.email,
			u.full_name,
			aur.roles
		FROM
			pauth_user AS u
		LEFT OUTER JOIN
			agged_user_roles AS aur
		ON
			u.id = aur.user_id
	`

	rows, err := hsqlx.SelectCtx[DBOutputUser](ctx, p.db, stmt)
	if err != nil {
		return nil, fmt.Errorf("error selecting: %w", err)
	}

	return hlp.Map(rows, func(r DBOutputUser, _ int) *pbv1beta1.User {
		return DBOutputUserToPBUser(r)
	}), nil
}

func (p *Postgres) SetUserPassword(ctx context.Context, req *SetUserPasswordRequest) error {
	return p.setUserPassword(ctx, p.db, req.UserId, req.HashedPassword)
}

func (p *Postgres) UpdateUser(ctx context.Context, user *pbv1beta1.User) error {
	return p.writeUser(ctx, p.db, user)
}

func (p *Postgres) DeleteUser(ctx context.Context, req *pbv1beta1.DeleteUserRequest) error {
	stmt := `
		DELETE FROM
			pauth_user
		WHERE
			id = :user_id
	`
	args := map[string]any{
		"user_id": req.UserId,
	}
	if _, err := p.db.NamedExecContext(ctx, stmt, args); err != nil {
		return fmt.Errorf("error deleting: %w", err)
	}

	return nil
}

func (p *Postgres) ListUserRoles(ctx context.Context, userId string) ([]string, error) {
	stmt := `
		SELECT
			*
		FROM
			pauth_user_role
		WHERE
			user_id = :user_id
	`
	args := map[string]any{
		"user_id": userId,
	}
	fmt.Println(args)

	rows, err := hsqlx.SelectNamedCtx[DBUserRole](ctx, p.db, stmt, args)
	if err != nil {
		return nil, fmt.Errorf("error selecting: %w", err)
	}

	return hlp.Map(rows, func(r DBUserRole, _ int) string {
		return r.Role
	}), nil
}

func (p *Postgres) GrantUserRoles(ctx context.Context, req *pbv1beta1.GrantUserRoleRequest) error {
	stmt := `
		INSERT INTO
			pauth_user_role
			(
				user_id,
				role
			)
		VALUES
			(
				:user_id,
				:role
			)
		ON CONFLICT ON CONSTRAINT
			pauth_user_role_pk
		DO
			NOTHING
	`
	if _, err := p.db.NamedExecContext(ctx, stmt, GrantUserRoleRequestToDBUserRole(req)); err != nil {
		return fmt.Errorf("error inserting: %w", err)
	}
	return nil
}

func (p *Postgres) RevokeUserRoles(ctx context.Context, req *pbv1beta1.RevokeUserRoleRequest) error {
	stmt := `
		DELETE FROM
			pauth_user_role
		WHERE
			user_id = :user_id AND
			role = :role
	`
	args := map[string]any{
		"user_id": req.UserId,
		"role":    req.Role,
	}
	if _, err := p.db.NamedExecContext(ctx, stmt, args); err != nil {
		return fmt.Errorf("error deleting: %w", err)
	}
	return nil
}

func (p *Postgres) GetActiveSession(ctx context.Context, sessionKey string) (*Session, error) {
	stmt := `
		WITH agged_user_roles AS (
			SELECT
				user_id,
				ARRAY_AGG(role) AS roles
			FROM
				pauth_user_role
			GROUP BY
				user_id
		)
		SELECT
			us.id AS session_id,
			us.expires_at,
			u.id,
			u.email,
			u.full_name,
			aur.roles
		FROM
			pauth_user_session AS us
		JOIN
			pauth_user AS u
		ON
			us.user_id = u.id
		LEFT OUTER JOIN
			agged_user_roles AS aur
		ON
			u.id = aur.user_id
		WHERE
			us.id = :session_key AND
			us.expires_at > :now
	`
	args := map[string]any{
		"session_key": sessionKey,
		"now":         p.now(),
	}

	rows, err := hsqlx.RequireExactSelectNamedCtx[DBOutputSession](ctx, 1, p.db, stmt, args)
	if err != nil {
		if errors.Is(err, hsqlx.ErrNotFoundError) {
			return nil, ErrSessionUnknownOrInactiveError
		}
		return nil, fmt.Errorf("error selecting: %w", err)
	}

	return DBOutputSessionToSession(rows[0]), nil
}

func (p *Postgres) CreateSession(ctx context.Context, req *CreateSessionRequest) error {
	stmt := `
		INSERT INTO
			pauth_user_session
			(
				id,
				user_id, 
				expires_at
			)
		VALUES
			(
				:id,
				:user_id, 
				:expires_at
			)
	`
	if _, err := p.db.NamedExecContext(ctx, stmt, CreateSessionRequestToDBSession(req)); err != nil {
		return fmt.Errorf("error inserting: %w", err)
	}

	return nil
}

func (p *Postgres) RemoveSession(ctx context.Context, sessionKey string) error {
	stmt := `
		DELETE FROM
			pauth_user_session
		WHERE
			id = :session_key
	`
	args := map[string]any{
		"session_key": sessionKey,
	}

	if _, err := p.db.NamedExecContext(ctx, stmt, args); err != nil {
		return fmt.Errorf("error deleting: %w", err)
	}

	return nil
}
