package storage

import (
	"database/sql"
	"github.com/lib/pq"
	"slices"
	"time"

	pbv1beta1 "github.com/nicjohnson145/pauth/gen/go/pauth/v1beta1"
	hsqlx "github.com/nicjohnson145/hlp/sqlx"
)

type Session struct {
	ID   string
	User *pbv1beta1.User
}

type DBUser struct {
	ID       string           `db:"id"`
	Email    sql.Null[string] `db:"email"`
	FullName sql.Null[string] `db:"full_name"`
}

func PBUserToDBUser(usr *pbv1beta1.User) DBUser {
	return DBUser{
		ID:       usr.Id,
		Email:    hsqlx.PointerToSqlNull(usr.Email),
		FullName: hsqlx.PointerToSqlNull(usr.FullName),
	}
}

type DBOutputUser struct {
	DBUser
	Roles pq.StringArray `db:"roles"`
}

func DBOutputUserToPBUser(row DBOutputUser) *pbv1beta1.User {
	var roles []string
	if len(row.Roles) > 0 {
		roles = slices.Sorted(slices.Values(row.Roles))
	}

	return &pbv1beta1.User{
		Id:       row.ID,
		Email:    hsqlx.SqlNullToPointer(row.Email),
		FullName: hsqlx.SqlNullToPointer(row.FullName),
		Roles:    roles,
	}
}

type DBOutputUserWithPassword struct {
	DBOutputUser
	Password sql.Null[string] `db:"password"`
}

func DBOutputUserWithPasswordToLoginInfo(row DBOutputUserWithPassword) *LoginInfo {
	return &LoginInfo{
		User:           DBOutputUserToPBUser(row.DBOutputUser),
		StoredPassword: row.Password.V,
	}
}

type DBUserRole struct {
	UserID string `db:"user_id"`
	Role   string `db:"role"`
}

func GrantUserRoleRequestToDBUserRole(req *pbv1beta1.GrantUserRoleRequest) DBUserRole {
	return DBUserRole{
		UserID: req.UserId,
		Role:   req.Role,
	}
}

type DBOutputSession struct {
	DBOutputUser
	ID        string    `db:"session_id"`
	ExpiresAt time.Time `db:"expires_at"`
}

func DBOutputSessionToSession(row DBOutputSession) *Session {
	return &Session{
		ID:   row.ID,
		User: DBOutputUserToPBUser(row.DBOutputUser),
	}
}

type DBSession struct {
	ID        string    `db:"id"`
	UserID    string    `db:"user_id"`
	ExpiresAt time.Time `db:"expires_at"`
}

func CreateSessionRequestToDBSession(req *CreateSessionRequest) DBSession {
	return DBSession{
		ID:        req.Session.ID,
		UserID:    req.Session.User.Id,
		ExpiresAt: req.ActiveUntil,
	}
}
