package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/go-logr/logr"
	pbv1beta1 "github.com/nicjohnson145/pauth/gen/go/pauth/v1beta1"
	pbv1beta1connect "github.com/nicjohnson145/pauth/gen/go/pauth/v1beta1/pauthv1beta1connect"
	"github.com/nicjohnson145/pauth/internal/storage"
	"github.com/nicjohnson145/hlp"
	"github.com/nicjohnson145/hlp/set"
	"github.com/oklog/ulid/v2"
	"go.einride.tech/aip/fieldmask"
)

var (
	ErrLoginError            = errors.New("incorrect identifier/password combination")
	ErrEndpointDisabledError = errors.New("endpoint disabled")
)

type ServiceConfig struct {
	Store storage.Storer
	// PurgeEnabled enables the purge endpoint. This endpoint should never be enabled on a non-testing deployment
	PurgeEnabled bool
	// InitialAdminEmail is the email for the initial bootstrap user
	InitialAdminEmail string
	// InitialAdminPassword is the password for the initial bootstrap user
	InitialAdminPassword string
	// InitialAdminRoles are the roles given to the initial admin, defaults to RoleAdministrator
	InitialAdminRoles []string
	// CreateUserRoles are roles that are allowed to create other users, defaults to RoleAdministrator
	CreateUserRoles *set.Set[string]
	// ReadUserRoles are the roles that are allowed to read users other than themselves, defautls to RoleAdministrator
	ReadUserRoles *set.Set[string]
	// ListUserRoles are roles that are allowed to list all users on the platform, defaults to RoleAdministrator
	ListUserRoles *set.Set[string]
	// SetUserPasswordRoles are roles that are allowed to set the passwords for other users, defaults to RoleAdministrator
	SetUserPasswordRoles *set.Set[string]
	// UpdateUserRoles are roles that are allowed to update information about other users, defaults to RoleAdministrator
	UpdateUserRoles *set.Set[string]
	// DeleteUserRoles are roles that are allowed to delete users, defaults to RoleAdministrator
	DeleteUserRoles *set.Set[string]
	// GrantUserRoles are roles that are allowed to grant roles to other users, defaults to RoleAdministrator
	GrantUserRoles *set.Set[string]
	// RevokeUserRoles are roles that are allowed to revoke roles from other users, defaults to RoleAdministrator
	RevokeUserRoles *set.Set[string]
	// SessionLifetime is how long a given session is valid for. If not given defaults to 7 days
	SessionLifetime *time.Duration
	// NowFunc is using to override what "now" is for session duration calcuation. Typically only needed for testing
	NowFunc func() time.Time
}

func NewService(conf ServiceConfig) *Service {
	defaultSet := func(opt *set.Set[string]) *set.Set[string] {
		if opt != nil {
			return opt
		}
		return set.New(RoleAdministrator)
	}

	sessionLife := conf.SessionLifetime
	if sessionLife == nil || (*sessionLife).Nanoseconds() == 0 {
		sessionLife = hlp.Ptr(24 * 7 * time.Hour)
	}

	now := conf.NowFunc
	if now == nil {
		now = func() time.Time {
			return time.Now().UTC()
		}
	}

	adminRoles := conf.InitialAdminRoles
	if adminRoles == nil {
		adminRoles = []string{RoleAdministrator}
	}

	return &Service{
		store:                conf.Store,
		initialAdminEmail:    conf.InitialAdminEmail,
		initialAdminPassword: conf.InitialAdminPassword,
		initialAdminRoles:    adminRoles,
		purgeEnabled:         conf.PurgeEnabled,
		createUserRoles:      defaultSet(conf.CreateUserRoles),
		readUserRoles:        defaultSet(conf.ReadUserRoles),
		listUserRoles:        defaultSet(conf.ListUserRoles),
		setUserPasswordRoles: defaultSet(conf.SetUserPasswordRoles),
		updateUserRoles:      defaultSet(conf.UpdateUserRoles),
		deleteUserRoles:      defaultSet(conf.DeleteUserRoles),
		grantUserRoles:       defaultSet(conf.GrantUserRoles),
		revokeUserRoles:      defaultSet(conf.RevokeUserRoles),
		sessionLife:          *sessionLife,
		now:                  now,
	}
}

type Service struct {
	pbv1beta1connect.UnimplementedPAuthServiceHandler

	store                storage.Storer
	initialAdminEmail    string
	initialAdminPassword string
	initialAdminRoles    []string
	purgeEnabled         bool
	createUserRoles      *set.Set[string]
	readUserRoles        *set.Set[string]
	listUserRoles        *set.Set[string]
	setUserPasswordRoles *set.Set[string]
	updateUserRoles      *set.Set[string]
	deleteUserRoles      *set.Set[string]
	grantUserRoles       *set.Set[string]
	revokeUserRoles      *set.Set[string]
	sessionLife          time.Duration
	now                  func() time.Time
}

func (s *Service) logError(ctx context.Context, err error, msg string) error {
	log := logr.FromContextOrDiscard(ctx)

	outMsg := msg
	if outMsg == "" {
		outMsg = "an error occurred"
	}

	log.Error(errors.New(outMsg), msg, "raw_error", err.Error())

	switch true {
	default:
		return err
	}
}

func (s *Service) ensureHasOneOfRoles(ctx context.Context, roles *set.Set[string]) error {
	session, err := SesssionFromContext(ctx)
	if err != nil {
		return fmt.Errorf("error extracting session: %w", err)
	}

	if set.New(session.User.Roles...).Intersection(roles).Count() == 0 {
		return ErrUnauthorizedError
	}

	return nil
}

func (s *Service) ensureTargetUserOrHasRole(ctx context.Context, userID *string, roles *set.Set[string]) error {
	session, err := SesssionFromContext(ctx)
	if err != nil {
		return fmt.Errorf("error extracting session: %w", err)
	}

	// If we have no user id, the action is targeted at "self", so let it happen
	if userID == nil {
		return nil
	}

	// If we do have a userid, short circuit in the case where the user id matches the sessions user id
	if *userID == session.User.Id {
		return nil
	}

	// Otherwise, we're trying to modify someone else, ensure the session has the attribute
	if set.New(session.User.Roles...).Intersection(roles).Count() > 0 {
		return nil
	}

	// If not, then you cant
	return ErrUnauthorizedError
}

func (s *Service) normalizeUserID(ctx context.Context, userID *string) (string, error) {
	if userID != nil {
		return *userID, nil
	}

	session, err := SesssionFromContext(ctx)
	if err != nil {
		return "", s.logError(ctx, err, "error extracting session")
	}
	return session.User.Id, nil
}

func (s *Service) Bootstrap(ctx context.Context) (bool, error) {
	// Check if we've already got a user configured, i.e its a restart of an existing service
	_, err := s.store.ReadLoginInfo(ctx, nil, &s.initialAdminEmail)
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, storage.ErrUnknownUserError) {
		return false, fmt.Errorf("error checking bootstrap user: %w", err)
	}

	// Otherwise, make the admin
	pw, err := HashPassword(s.initialAdminPassword)
	if err != nil {
		return false, err
	}
	userID := ulid.Make().String()

	err = s.store.CreateUser(ctx, &storage.CreateUserRequest{
		User: &pbv1beta1.User{
			Id:    userID,
			Email: hlp.Ptr(s.initialAdminEmail),
		},
		HashedPassword: hlp.Ptr(pw),
	})
	if err != nil {
		return false, fmt.Errorf("error creating admin user: %w", err)
	}

	// And grant them the admin roles
	for _, role := range s.initialAdminRoles {
		if err := s.store.GrantUserRoles(ctx, &pbv1beta1.GrantUserRoleRequest{UserId: userID, Role: role}); err != nil {
			return false, fmt.Errorf("error granting admin role '%v': %w", role, err)
		}
	}

	return true, nil
}

func (s *Service) Purge(ctx context.Context, req *connect.Request[pbv1beta1.PurgeRequest]) (*connect.Response[pbv1beta1.PurgeResponse], error) {
	if !s.purgeEnabled {
		return nil, s.logError(ctx, ErrEndpointDisabledError, "purge is disabled")
	}

	if err := s.store.Purge(ctx); err != nil {
		return nil, s.logError(ctx, err, "purge is disabled")
	}

	if _, err := s.Bootstrap(ctx); err != nil {
		return nil, s.logError(ctx, err, "error rebootstrapping")
	}

	return connect.NewResponse(&pbv1beta1.PurgeResponse{}), nil
}

func (s *Service) CreateUser(ctx context.Context, req *connect.Request[pbv1beta1.CreateUserRequest]) (*connect.Response[pbv1beta1.CreateUserResponse], error) {
	if err := s.ensureHasOneOfRoles(ctx, s.createUserRoles); err != nil {
		return nil, s.logError(ctx, err, "error ensuring role")
	}

	// Set id if not given
	if req.Msg.User.Id == "" {
		req.Msg.User.Id = ulid.Make().String()
	}

	var hashedPw *string
	if req.Msg.Password != nil {
		hashed, err := HashPassword(*req.Msg.Password)
		if err != nil {
			return nil, s.logError(ctx, err, "error hashing provided password")
		}
		hashedPw = hlp.Ptr(hashed)
	}

	sReq := &storage.CreateUserRequest{
		User:           req.Msg.User,
		HashedPassword: hashedPw,
	}
	if err := s.store.CreateUser(ctx, sReq); err != nil {
		return nil, s.logError(ctx, err, "error creating user")
	}

	return connect.NewResponse(&pbv1beta1.CreateUserResponse{
		User: req.Msg.User,
	}), nil
}

func (s *Service) ReadUser(ctx context.Context, req *connect.Request[pbv1beta1.ReadUserReqeust]) (*connect.Response[pbv1beta1.ReadUserResponse], error) {
	if err := s.ensureTargetUserOrHasRole(ctx, req.Msg.UserId, s.readUserRoles); err != nil {
		return nil, s.logError(ctx, err, "error ensuring access")
	}

	userID, err := s.normalizeUserID(ctx, req.Msg.UserId)
	if err != nil {
		return nil, s.logError(ctx, err, "error normalizing user id")
	}

	user, err := s.store.ReadUser(ctx, userID)
	if err != nil {
		return nil, s.logError(ctx, err, "error reading")
	}

	return connect.NewResponse(&pbv1beta1.ReadUserResponse{
		User: user,
	}), nil
}

func (s *Service) ListUsers(ctx context.Context, req *connect.Request[pbv1beta1.ListUsersRequest]) (*connect.Response[pbv1beta1.ListUsersResponse], error) {
	if err := s.ensureHasOneOfRoles(ctx, s.listUserRoles); err != nil {
		return nil, s.logError(ctx, err, "error ensuring role")
	}

	users, err := s.store.ListUsers(ctx, req.Msg)
	if err != nil {
		return nil, s.logError(ctx, err, "error listing")
	}

	return connect.NewResponse(&pbv1beta1.ListUsersResponse{
		Users: users,
	}), nil
}

func (s *Service) SetUserPassword(ctx context.Context, req *connect.Request[pbv1beta1.SetUserPasswordRequest]) (*connect.Response[pbv1beta1.SetUserPasswordResponse], error) {
	if err := s.ensureTargetUserOrHasRole(ctx, req.Msg.UserId, s.setUserPasswordRoles); err != nil {
		return nil, s.logError(ctx, err, "error ensuring access")
	}

	userID, err := s.normalizeUserID(ctx, req.Msg.UserId)
	if err != nil {
		return nil, s.logError(ctx, err, "error normalizing user id")
	}

	hashedPw, err := HashPassword(req.Msg.Password)
	if err != nil {
		return nil, s.logError(ctx, err, "error hashing password")
	}

	sReq := &storage.SetUserPasswordRequest{
		UserId:         userID,
		HashedPassword: hashedPw,
	}
	if err := s.store.SetUserPassword(ctx, sReq); err != nil {
		return nil, s.logError(ctx, err, "error setting password")
	}

	return connect.NewResponse(&pbv1beta1.SetUserPasswordResponse{}), nil
}

func (s *Service) UpdateUser(ctx context.Context, req *connect.Request[pbv1beta1.UpdateUserRequest]) (*connect.Response[pbv1beta1.UpdateUserResponse], error) {
	if err := s.ensureTargetUserOrHasRole(ctx, &req.Msg.User.Id, s.updateUserRoles); err != nil {
		return nil, s.logError(ctx, err, "error ensuring access")
	}

	updatedUser := req.Msg.User
	if req.Msg.FieldMask != nil {
		usr, err := s.store.ReadUser(ctx, req.Msg.User.Id)
		if err != nil {
			return nil, s.logError(ctx, err, "error reading existing user info")
		}
		fieldmask.Update(req.Msg.FieldMask, usr, req.Msg.User)
		updatedUser = usr
	}

	if err := s.store.UpdateUser(ctx, updatedUser); err != nil {
		return nil, s.logError(ctx, err, "error updating")
	}

	return connect.NewResponse(&pbv1beta1.UpdateUserResponse{}), nil
}

func (s *Service) DeleteUser(ctx context.Context, req *connect.Request[pbv1beta1.DeleteUserRequest]) (*connect.Response[pbv1beta1.DeleteUserResponse], error) {
	if err := s.ensureHasOneOfRoles(ctx, s.deleteUserRoles); err != nil {
		return nil, s.logError(ctx, err, "error ensuring role")
	}

	if err := s.store.DeleteUser(ctx, req.Msg); err != nil {
		return nil, s.logError(ctx, err, "error deleting")
	}

	return connect.NewResponse(&pbv1beta1.DeleteUserResponse{}), nil
}

func (s *Service) Login(ctx context.Context, req *connect.Request[pbv1beta1.LoginRequest]) (*connect.Response[pbv1beta1.LoginResponse], error) {
	// Create a closure so we can log & error freely, but only respond to the client with pre-canned error messages
	// since this endpoint is unauthenticated and we dont want to leak information
	inner := func() (*pbv1beta1.LoginResponse, error) {
		// Get the password stored for the user
		info, err := s.store.ReadLoginInfo(ctx, req.Msg.UserId, req.Msg.Email)
		if err != nil {
			return nil, s.logError(ctx, err, "error getting user")
		}

		// Check if it matches
		if !PasswordsMatch(req.Msg.Password, info.StoredPassword) {
			return nil, s.logError(ctx, errors.New("password mismatch"), "incorrect login credentials")
		}

		// If it does, store their session and return the key to them
		sessionID := ulid.Make().String()
		sReq := &storage.CreateSessionRequest{
			Session: &storage.Session{
				ID:   sessionID,
				User: info.User,
			},
			ActiveUntil: s.now().Add(s.sessionLife),
		}
		if err := s.store.CreateSession(ctx, sReq); err != nil {
			return nil, s.logError(ctx, err, "error creating session")
		}

		return &pbv1beta1.LoginResponse{
			AccessKey: sessionID,
		}, nil
	}

	resp, err := inner()
	if err != nil {
		return nil, ErrLoginError
	}

	return connect.NewResponse(resp), nil
}

func (s *Service) ListUserRoles(ctx context.Context, req *connect.Request[pbv1beta1.ListUserRolesRequest]) (*connect.Response[pbv1beta1.ListUserRolesResponse], error) {
	if err := s.ensureTargetUserOrHasRole(ctx, req.Msg.UserId, s.updateUserRoles); err != nil {
		return nil, s.logError(ctx, err, "error ensuring access")
	}

	userID, err := s.normalizeUserID(ctx, req.Msg.UserId)
	if err != nil {
		return nil, s.logError(ctx, err, "error normalizing user id")
	}

	roles, err := s.store.ListUserRoles(ctx, userID)
	if err != nil {
		return nil, s.logError(ctx, err, "error reading user")
	}

	return connect.NewResponse(&pbv1beta1.ListUserRolesResponse{
		Roles: roles,
	}), nil
}

func (s *Service) GrantUserRole(ctx context.Context, req *connect.Request[pbv1beta1.GrantUserRoleRequest]) (*connect.Response[pbv1beta1.GrantUserRoleResponse], error) {
	if err := s.ensureHasOneOfRoles(ctx, s.grantUserRoles); err != nil {
		return nil, s.logError(ctx, err, "error ensuring role")
	}

	if err := s.store.GrantUserRoles(ctx, req.Msg); err != nil {
		return nil, s.logError(ctx, err, "error granting")
	}

	return connect.NewResponse(&pbv1beta1.GrantUserRoleResponse{}), nil
}

func (s *Service) RevokeUserRole(ctx context.Context, req *connect.Request[pbv1beta1.RevokeUserRoleRequest]) (*connect.Response[pbv1beta1.RevokeUserRoleResponse], error) {
	if err := s.ensureHasOneOfRoles(ctx, s.revokeUserRoles); err != nil {
		return nil, s.logError(ctx, err, "error ensuring role")
	}

	if err := s.store.RevokeUserRoles(ctx, req.Msg); err != nil {
		return nil, s.logError(ctx, err, "error granting")
	}

	return connect.NewResponse(&pbv1beta1.RevokeUserRoleResponse{}), nil
}

func (s *Service) IsKeyActive(ctx context.Context, req *connect.Request[pbv1beta1.IsKeyActiveRequest]) (*connect.Response[pbv1beta1.IsKeyActiveResponse], error) {
	// Implement as a closure to avoid leaking information since this endpoint is public
	inner := func() bool {
		_, err := s.store.GetActiveSession(ctx, req.Msg.AccessKey)
		if err != nil {
			if errors.Is(err, storage.ErrSessionUnknownOrInactiveError) {
				return false
			}
			_ = s.logError(ctx, err, "error checking session validity")
			return false
		}
		return true
	}

	return connect.NewResponse(&pbv1beta1.IsKeyActiveResponse{
		Active: inner(),
	}), nil
}
