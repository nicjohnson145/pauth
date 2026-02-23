package storage

import (
	"context"
	"log"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/nicjohnson145/hlp"
	pauthv1beta1 "github.com/nicjohnson145/pauth/gen/go/pauth/v1beta1"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func nowClosure() (func() time.Time, func(time.Time)) {
	var closureTime time.Time
	getFunc := func() time.Time {
		return closureTime
	}
	setFunc := func(t time.Time) {
		closureTime = t
	}

	return getFunc, setFunc
}

func TestPostgres(t *testing.T) {
	if testing.Short() {
		t.Skipf("postgres integration tests are not quick")
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dbName := "pauth"
	dbUser := "pauth_usr"
	dbPassword := "some-password"

	postgresContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase(dbName),
		postgres.WithUsername(dbUser),
		postgres.WithPassword(dbPassword),
		postgres.BasicWaitStrategies(),
	)
	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(postgresContainer); err != nil {
			log.Printf("failed to terminate container: %s", err)
		}
	})
	require.NoError(t, err, "failed to start container")

	t.Log(hlp.Must(postgresContainer.Inspect(ctx)).NetworkSettings.Ports)

	t.Cleanup(func() {
		viper.Reset()
	})

	portMap := hlp.Must(postgresContainer.Inspect(ctx)).NetworkSettings.Ports
	pgPort := (portMap["5432/tcp"])[0].HostPort

	getTime, setTime := nowClosure()
	//store, cleanup, err := newFromEnvWithNow(zerolog.New(zerolog.NewTestWriter(t)), getTime)
	store, cleanup, err := NewPostgresStore(PostgresStoreOpts{
		NowFunc: getTime,
		ConnectionOpts: &PostgresStoreConnectionOpts{
			Host:     "localhost",
			Port:     hlp.Must(strconv.Atoi(pgPort)),
			User:     dbUser,
			Password: dbPassword,
			DBName:   dbName,
			SSLMode:  "disable",
		},
	})
	t.Cleanup(cleanup)
	require.NoError(t, err)

	integrationTest(t, store, setTime)
}

func TestMemory(t *testing.T) {
	getTime, setTime := nowClosure()
	integrationTest(t, NewMemory(MemoryConfig{
		Now: getTime,
	}), setTime)
}

func integrationTest(t *testing.T, store Storer, setNow func(time.Time)) {
	protoMustEqual := func(t *testing.T, want any, got any) {
		t.Helper()

		defaultOpts := []cmp.Option{protocmp.Transform()}

		if diff := cmp.Diff(want, got, defaultOpts...); diff != "" {
			t.Logf("Mismatch (-want +got):\n%s", diff)
			t.FailNow()
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("basic crud", func(t *testing.T) {
		require.NoError(t, store.Purge(ctx))

		baseUser := &pauthv1beta1.User{
			Id:    "user-one",
			Email: hlp.Ptr("user-one@example.com"),
		}

		// create a user
		require.NoError(t, store.CreateUser(ctx, &CreateUserRequest{
			User:           baseUser,
			HashedPassword: hlp.Ptr("some-hashed-password"),
		}))

		// read them back
		readUser, err := store.ReadUser(ctx, "user-one")
		require.NoError(t, err)
		protoMustEqual(t, baseUser, readUser)

		// read their login info by id
		userIDLoginInfo, err := store.ReadLoginInfo(ctx, hlp.Ptr("user-one"), nil)
		require.NoError(t, err)
		require.Equal(t, userIDLoginInfo.StoredPassword, "some-hashed-password")
		protoMustEqual(t, baseUser, userIDLoginInfo.User)

		// read their login info by email
		userIDLoginInfo, err = store.ReadLoginInfo(ctx, nil, hlp.Ptr("user-one@example.com"))
		require.NoError(t, err)
		require.Equal(t, userIDLoginInfo.StoredPassword, "some-hashed-password")
		protoMustEqual(t, baseUser, userIDLoginInfo.User)

		// create another user
		newUser := &pauthv1beta1.User{
			Id:    "user-two",
			Email: hlp.Ptr("user-twoe@example.com"),
		}
		require.NoError(t, store.CreateUser(ctx, &CreateUserRequest{
			User:           newUser,
			HashedPassword: hlp.Ptr("other-hashed-password"),
		}))

		// list our users out
		listUsers, err := store.ListUsers(ctx, &pauthv1beta1.ListUsersRequest{})
		require.NoError(t, err)
		protoMustEqual(
			t,
			[]*pauthv1beta1.User{
				baseUser,
				newUser,
			},
			listUsers,
		)

		// update one of them
		newBaseUser := proto.Clone(baseUser).(*pauthv1beta1.User)
		newBaseUser.FullName = hlp.Ptr("New Base User")
		require.NoError(t, err, store.UpdateUser(ctx, newBaseUser))

		// Should read as the new bits
		readUser, err = store.ReadUser(ctx, "user-one")
		require.NoError(t, err)
		protoMustEqual(t, newBaseUser, readUser)

		// Delete one
		require.NoError(t, store.DeleteUser(ctx, &pauthv1beta1.DeleteUserRequest{UserId: "user-one"}))

		// Confirm delete
		listUsers, err = store.ListUsers(ctx, &pauthv1beta1.ListUsersRequest{})
		require.NoError(t, err)
		protoMustEqual(
			t,
			[]*pauthv1beta1.User{
				newUser,
			},
			listUsers,
		)
	})

	t.Run("roles", func(t *testing.T) {
		require.NoError(t, store.Purge(ctx))

		baseUser := &pauthv1beta1.User{
			Id:    "user-one",
			Email: hlp.Ptr("user-one@example.com"),
		}

		baseWithRoles := func(roles ...string) *pauthv1beta1.User {
			u := proto.Clone(baseUser).(*pauthv1beta1.User)
			u.Roles = roles
			return u
		}

		// create a user
		require.NoError(t, store.CreateUser(ctx, &CreateUserRequest{
			User:           baseUser,
			HashedPassword: hlp.Ptr("some-hashed-password"),
		}))

		// grant a role
		require.NoError(t, store.GrantUserRoles(ctx, &pauthv1beta1.GrantUserRoleRequest{
			UserId: "user-one",
			Role:   "role-one",
		}))

		// list roles for that user
		roles, err := store.ListUserRoles(ctx, "user-one")
		require.NoError(t, err)
		require.Equal(t, []string{"role-one"}, roles)

		// Read that user, roles should show
		user, err := store.ReadUser(ctx, "user-one")
		require.NoError(t, err)
		protoMustEqual(t, baseWithRoles("role-one"), user)

		// list users, roles should show
		users, err := store.ListUsers(ctx, &pauthv1beta1.ListUsersRequest{})
		require.NoError(t, err)
		protoMustEqual(t, []*pauthv1beta1.User{baseWithRoles("role-one")}, users)

		// revoke that role
		require.NoError(t, store.RevokeUserRoles(ctx, &pauthv1beta1.RevokeUserRoleRequest{
			UserId: "user-one",
			Role:   "role-one",
		}))

		// Read that user, roles should be gone
		user, err = store.ReadUser(ctx, "user-one")
		require.NoError(t, err)
		protoMustEqual(t, baseWithRoles(), user)

		// list users, roles should be gone
		users, err = store.ListUsers(ctx, &pauthv1beta1.ListUsersRequest{})
		require.NoError(t, err)
		protoMustEqual(t, []*pauthv1beta1.User{baseWithRoles()}, users)
	})

	t.Run("sessions", func(t *testing.T) {
		require.NoError(t, store.Purge(ctx))

		baseUser := &pauthv1beta1.User{
			Id:    "user-one",
			Email: hlp.Ptr("user-one@example.com"),
		}

		now := time.Date(2025, 5, 15, 12, 30, 0, 0, time.UTC)
		nowPlus10s := now.Add(10 * time.Second)
		nowPlus20s := now.Add(20 * time.Second)

		setNow(now)

		baseWithRoles := func(roles ...string) *pauthv1beta1.User {
			u := proto.Clone(baseUser).(*pauthv1beta1.User)
			u.Roles = roles
			return u
		}

		// create a user
		require.NoError(t, store.CreateUser(ctx, &CreateUserRequest{
			User:           baseUser,
			HashedPassword: hlp.Ptr("some-hashed-password"),
		}))

		// create a session with that user
		require.NoError(t, store.CreateSession(ctx, &CreateSessionRequest{
			Session: &Session{
				ID:   "session-one",
				User: baseWithRoles(),
			},
			ActiveUntil: nowPlus10s,
		}))

		// Read it
		session, err := store.GetActiveSession(ctx, "session-one")
		require.NoError(t, err)
		require.Equal(t, "session-one", session.ID)
		protoMustEqual(t, baseWithRoles(), session.User)

		// advance time
		setNow(nowPlus20s)

		// read it again, it should error
		_, err = store.GetActiveSession(ctx, "session-one")
		require.ErrorIs(t, err, ErrSessionUnknownOrInactiveError)
	})

	t.Run("sessions + roles", func(t *testing.T) {
		require.NoError(t, store.Purge(ctx))

		baseUser := &pauthv1beta1.User{
			Id:    "user-one",
			Email: hlp.Ptr("user-one@example.com"),
		}

		baseWithRoles := func(roles ...string) *pauthv1beta1.User {
			u := proto.Clone(baseUser).(*pauthv1beta1.User)
			u.Roles = roles
			return u
		}

		// create a user
		require.NoError(t, store.CreateUser(ctx, &CreateUserRequest{
			User:           baseUser,
			HashedPassword: hlp.Ptr("some-hashed-password"),
		}))

		now := time.Date(2025, 5, 15, 12, 30, 0, 0, time.UTC)
		nowPlus10s := now.Add(10 * time.Second)

		setNow(now)

		// create a session with that user
		require.NoError(t, store.CreateSession(ctx, &CreateSessionRequest{
			Session: &Session{
				ID:   "session-one",
				User: baseWithRoles(),
			},
			ActiveUntil: nowPlus10s,
		}))

		// now grant that user a new role
		require.NoError(t, store.GrantUserRoles(ctx, &pauthv1beta1.GrantUserRoleRequest{
			UserId: "user-one",
			Role:   "role-one",
		}))

		// Reading their session should result in their roles being updated
		session, err := store.GetActiveSession(ctx, "session-one")
		require.NoError(t, err)
		require.Equal(t, "session-one", session.ID)
		protoMustEqual(t, baseWithRoles("role-one"), session.User)
	})
}
