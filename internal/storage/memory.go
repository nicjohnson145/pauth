package storage

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	pbv1beta1 "github.com/nicjohnson145/pauth/gen/go/pauth/v1beta1"
	"github.com/nicjohnson145/hlp"
	"github.com/nicjohnson145/hlp/set"
	"google.golang.org/protobuf/proto"
)

type MemoryConfig struct {
	Now func() time.Time
}

func NewMemory(conf MemoryConfig) *Memory {
	now := conf.Now
	if now == nil {
		now = func() time.Time {
			return time.Now().UTC()
		}
	}

	m := &Memory{
		now: now,
		mu:  &sync.RWMutex{},
	}

	m.init()
	return m
}

type memoryUser struct {
	User           *pbv1beta1.User
	HashedPassword *string
}

type memorySession struct {
	Session    *Session
	Expiration time.Time
}

type Memory struct {
	now func() time.Time

	mu        *sync.RWMutex
	users     map[string]memoryUser
	userRoles map[string]*set.Set[string]
	sessions  map[string]memorySession
}

func (m *Memory) init() {
	m.users = map[string]memoryUser{}
	m.userRoles = map[string]*set.Set[string]{}
	m.sessions = map[string]memorySession{}
}

func (m *Memory) Purge(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	return nil
}

func (m *Memory) CreateUser(ctx context.Context, req *CreateUserRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.users[req.User.Id]; ok {
		return ErrUserAlreadyExistsError
	}

	m.users[req.User.Id] = memoryUser{
		User:           req.User,
		HashedPassword: req.HashedPassword,
	}

	return nil
}

func (m *Memory) ReadUser(ctx context.Context, userId string) (*pbv1beta1.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.readUser(userId)
}

func (m *Memory) readUser(userId string) (*pbv1beta1.User, error) {
	user, ok := m.users[userId]
	if !ok {
		return nil, ErrUnknownUserError
	}

	outUser := proto.Clone(user.User).(*pbv1beta1.User)
	if roleSet, ok := m.userRoles[userId]; ok {
		outUser.Roles = roleSet.AsSlice()
	}

	return outUser, nil
}

func (m *Memory) ReadLoginInfo(ctx context.Context, userID *string, email *string) (*LoginInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var usr memoryUser
	switch true {
	case userID != nil:
		u, ok := m.users[*userID]
		if !ok {
			return nil, ErrUnknownUserError
		}
		usr = u
	case email != nil:
		found := false
		for _, u := range m.users {
			if u.User.Email != nil && *u.User.Email == *email {
				usr = u
				found = true
				break
			}
		}
		if !found {
			return nil, ErrUnknownUserError
		}
	default:
		return nil, fmt.Errorf("unsupported search configuration")
	}

	if usr.HashedPassword == nil {
		return nil, ErrNoPasswordConfiguredError
	}

	// Set the user roles
	outUser := proto.Clone(usr.User).(*pbv1beta1.User)
	if roleSet, ok := m.userRoles[usr.User.Id]; ok {
		outUser.Roles = roleSet.AsSlice()
	}

	return &LoginInfo{
		User:           outUser,
		StoredPassword: *usr.HashedPassword,
	}, nil
}

func (m *Memory) ListUsers(ctx context.Context, req *pbv1beta1.ListUsersRequest) ([]*pbv1beta1.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	userList := hlp.Map(hlp.Values(m.users), func(u memoryUser, _ int) *pbv1beta1.User {
		outUser := proto.Clone(u.User).(*pbv1beta1.User)
		if roleSet, ok := m.userRoles[u.User.Id]; ok {
			outUser.Roles = roleSet.AsSlice()
		}
		return outUser
	})
	slices.SortFunc(userList, func(a *pbv1beta1.User, b *pbv1beta1.User) int {
		return strings.Compare(a.Id, b.Id)
	})

	return userList, nil
}

func (m *Memory) SetUserPassword(ctx context.Context, req *SetUserPasswordRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, ok := m.users[req.UserId]
	if !ok {
		return ErrUnknownUserError
	}

	user.HashedPassword = hlp.Ptr(req.HashedPassword)
	m.users[req.UserId] = user

	return nil
}

func (m *Memory) UpdateUser(ctx context.Context, user *pbv1beta1.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	usr, ok := m.users[user.Id]
	if !ok {
		return ErrUnknownUserError
	}

	usr.User = user
	m.users[user.Id] = usr

	return nil
}

func (m *Memory) DeleteUser(ctx context.Context, req *pbv1beta1.DeleteUserRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.users, req.UserId)
	delete(m.userRoles, req.UserId)
	for key, session := range m.sessions {
		if session.Session.ID == req.UserId {
			delete(m.sessions, key)
		}
	}

	return nil
}

func (m *Memory) ListUserRoles(ctx context.Context, userId string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	roles, ok := m.userRoles[userId]
	if !ok {
		return []string{}, nil
	}
	return roles.AsSlice(), nil
}

func (m *Memory) GrantUserRoles(ctx context.Context, req *pbv1beta1.GrantUserRoleRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	roleSet, ok := m.userRoles[req.UserId]
	if !ok {
		roleSet = set.New[string]()
	}
	roleSet.Add(req.Role)

	m.userRoles[req.UserId] = roleSet

	return nil
}

func (m *Memory) RevokeUserRoles(ctx context.Context, req *pbv1beta1.RevokeUserRoleRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	roleSet, ok := m.userRoles[req.UserId]
	if !ok {
		return nil
	}
	roleSet.Remove(req.Role)

	m.userRoles[req.UserId] = roleSet

	return nil
}

func (m *Memory) GetActiveSession(ctx context.Context, sessionKey string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	memorySession, ok := m.sessions[sessionKey]
	if !ok {
		return nil, ErrSessionUnknownOrInactiveError
	}
	if m.now().After(memorySession.Expiration) {
		return nil, ErrSessionUnknownOrInactiveError
	}

	outUser, err := m.readUser(memorySession.Session.User.Id)
	if err != nil {
		return nil, fmt.Errorf("error reading user for session: %w", err)
	}

	return &Session{
		ID:   sessionKey,
		User: outUser,
	}, nil
}

func (m *Memory) CreateSession(ctx context.Context, req *CreateSessionRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sessions[req.Session.ID] = memorySession{
		Session:    req.Session,
		Expiration: req.ActiveUntil,
	}

	return nil
}

func (m *Memory) RemoveSession(ctx context.Context, sessionKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.sessions, sessionKey)

	return nil
}
