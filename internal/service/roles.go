package service

const (
	// Admins can peform certain "other user" actions, ex: setting the password for a user other than themselves. This
	// is the default role, although this can be overriden in the service config
	RoleAdministrator = "admin"
)
