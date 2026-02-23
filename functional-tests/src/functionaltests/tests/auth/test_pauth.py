from functionaltests import util
from pauth.pauth import v1beta1 as pauthv1beta1
from betterproto2 import unwrap
from testfixtures import compare
from typing import Any


class TestPauth(util.Base):
    GRANT_ADMIN_ALL = False

    def strip_ids(self, response) -> Any:
        if isinstance(response, pauthv1beta1.ListUsersResponse):
            for idx, _ in enumerate(response.users):
                response.users[idx].id = ""
            return response
        elif isinstance(response, pauthv1beta1.ReadUserResponse):
            unwrap(response.user).id = ""
            return response

        raise ValueError("unhandled type in strip_ids")

    def test_login(self):
        resp = util.execute_http(
            util.pauth_v1beta1_method("Login"),
            body=pauthv1beta1.LoginRequest(
                email=self.ADMIN_EMAIL,
                password=self.ADMIN_PASSWORD,
            ),
            response_shape=pauthv1beta1.LoginResponse,
        )
        self.assertNotEqual(resp.access_key, "")

    def test_create_user(self):
        # make a user as admin
        util.execute_http(
            util.pauth_v1beta1_method("CreateUser"),
            key=self.login(),
            body=pauthv1beta1.CreateUserRequest(
                user=pauthv1beta1.User(email="guy@example.com"),
                password="guy-password",
            ),
        )

        # try to login as said user
        self.login(email="guy@example.com", password="guy-password")

    def test_read_other_user(self):
        admin_key = self.login()

        # create a user
        create_resp = util.execute_http(
            util.pauth_v1beta1_method("CreateUser"),
            key=admin_key,
            body=pauthv1beta1.CreateUserRequest(
                user=pauthv1beta1.User(email="guy@example.com"),
                password="guy-password",
            ),
            response_shape=pauthv1beta1.CreateUserResponse,
        )

        # read that user as the admin
        read_resp = util.execute_http(
            util.pauth_v1beta1_method("ReadUser"),
            key=admin_key,
            body=pauthv1beta1.ReadUserReqeust(
                user_id=unwrap(create_resp.user).id,
            ),
            response_shape=pauthv1beta1.ReadUserResponse,
        )

        compare(
            actual=read_resp.user,
            expected=pauthv1beta1.User(
                id=unwrap(create_resp.user).id,
                email="guy@example.com",
            ),
        )

    def test_list_users(self):
        admin_key = self.login()

        # create a few users
        util.execute_http(
            util.pauth_v1beta1_method("CreateUser"),
            key=admin_key,
            body=pauthv1beta1.CreateUserRequest(
                user=pauthv1beta1.User(email="guy@example.com"),
                password="guy-password",
            ),
        )
        util.execute_http(
            util.pauth_v1beta1_method("CreateUser"),
            key=admin_key,
            body=pauthv1beta1.CreateUserRequest(
                user=pauthv1beta1.User(email="gal@example.com"),
                password="gal-password",
            ),
        )

        # list them out
        resp = util.execute_http(
            util.pauth_v1beta1_method("ListUsers"),
            key=admin_key,
            body=pauthv1beta1.ListUsersRequest(),
            response_shape=pauthv1beta1.ListUsersResponse,
        )
        # strip the IDs out for simplicity
        actual_users = []
        for u in resp.users:
            u.id = ""
            actual_users.append(u)

        compare(
            actual=actual_users,
            expected=[
                pauthv1beta1.User(email="admin@example.com", roles=["admin"]),
                pauthv1beta1.User(email="guy@example.com"),
                pauthv1beta1.User(email="gal@example.com"),
            ],
        )

    def test_set_user_password(self):
        admin_key = self.login()

        # make a user
        create_resp = util.execute_http(
            util.pauth_v1beta1_method("CreateUser"),
            key=admin_key,
            body=pauthv1beta1.CreateUserRequest(
                user=pauthv1beta1.User(email="guy@example.com"),
                password="guy-password",
            ),
            response_shape=pauthv1beta1.CreateUserResponse,
        )

        # update their password
        util.execute_http(
            util.pauth_v1beta1_method("SetUserPassword"),
            key=admin_key,
            body=pauthv1beta1.SetUserPasswordRequest(
                user_id=unwrap(create_resp.user).id,
                password="new-password",
            ),
        )

        # login with the new password
        self.login(email="guy@example.com", password="new-password")

    def test_update_user(self):
        admin_key = self.login()

        # make a user
        create_resp = util.execute_http(
            util.pauth_v1beta1_method("CreateUser"),
            key=admin_key,
            body=pauthv1beta1.CreateUserRequest(
                user=pauthv1beta1.User(email="guy@example.com"),
                password="guy-password",
            ),
            response_shape=pauthv1beta1.CreateUserResponse,
        )

        # update them
        util.execute_http(
            util.pauth_v1beta1_method("UpdateUser"),
            key=admin_key,
            body=pauthv1beta1.UpdateUserRequest(
                user=pauthv1beta1.User(
                    id=unwrap(create_resp.user).id,
                    email="guy@example.com",
                    full_name="Guy Example",
                ),
            ),
        )

        # read them back out
        read_resp = util.execute_http(
            util.pauth_v1beta1_method("ReadUser"),
            key=admin_key,
            body=pauthv1beta1.ReadUserReqeust(
                user_id=unwrap(create_resp.user).id,
            ),
            response_shape=pauthv1beta1.ReadUserResponse,
        )
        compare(
            actual=read_resp.user,
            expected=pauthv1beta1.User(
                id=unwrap(create_resp.user).id,
                email="guy@example.com",
                full_name="Guy Example",
            ),
        )

    def test_delete_user(self):
        admin_key = self.login()

        # create a few users
        guy_resp = util.execute_http(
            util.pauth_v1beta1_method("CreateUser"),
            key=admin_key,
            body=pauthv1beta1.CreateUserRequest(
                user=pauthv1beta1.User(email="guy@example.com"),
                password="guy-password",
            ),
            response_shape=pauthv1beta1.CreateUserResponse,
        )
        util.execute_http(
            util.pauth_v1beta1_method("CreateUser"),
            key=admin_key,
            body=pauthv1beta1.CreateUserRequest(
                user=pauthv1beta1.User(email="gal@example.com"),
                password="gal-password",
            ),
            response_shape=pauthv1beta1.CreateUserResponse,
        )

        # delete one of them
        util.execute_http(
            util.pauth_v1beta1_method("DeleteUser"),
            key=admin_key,
            body=pauthv1beta1.DeleteUserRequest(
                user_id=unwrap(guy_resp.user).id,
            ),
        )

        # list them out
        resp = self.strip_ids(
            util.execute_http(
                util.pauth_v1beta1_method("ListUsers"),
                key=admin_key,
                body=pauthv1beta1.ListUsersRequest(),
                response_shape=pauthv1beta1.ListUsersResponse,
            )
        )

        compare(
            actual=resp.users,
            expected=[
                pauthv1beta1.User(email="admin@example.com", roles=["admin"]),
                pauthv1beta1.User(email="gal@example.com"),
            ],
        )

    def test_grant_user_role(self):
        admin_key = self.login()

        # create a user
        guy_resp = util.execute_http(
            util.pauth_v1beta1_method("CreateUser"),
            key=admin_key,
            body=pauthv1beta1.CreateUserRequest(
                user=pauthv1beta1.User(email="guy@example.com"),
                password="guy-password",
            ),
            response_shape=pauthv1beta1.CreateUserResponse,
        )

        # grant them a role
        util.execute_http(
            util.pauth_v1beta1_method("GrantUserRole"),
            key=admin_key,
            body=pauthv1beta1.GrantUserRoleRequest(
                user_id=unwrap(guy_resp.user).id,
                role="some-role",
            ),
        )

        # read the user back
        read_resp = self.strip_ids(
            util.execute_http(
                util.pauth_v1beta1_method("ReadUser"),
                key=admin_key,
                body=pauthv1beta1.ReadUserReqeust(
                    user_id=unwrap(guy_resp.user).id,
                ),
                response_shape=pauthv1beta1.ReadUserResponse,
            )
        )
        compare(
            actual=read_resp.user,
            expected=pauthv1beta1.User(
                email="guy@example.com",
                roles=["some-role"],
            ),
        )

        # list the users
        resp = self.strip_ids(
            util.execute_http(
                util.pauth_v1beta1_method("ListUsers"),
                key=admin_key,
                body=pauthv1beta1.ListUsersRequest(),
                response_shape=pauthv1beta1.ListUsersResponse,
            )
        )

        compare(
            actual=resp.users,
            expected=[
                pauthv1beta1.User(email="admin@example.com", roles=["admin"]),
                pauthv1beta1.User(email="guy@example.com", roles=["some-role"]),
            ],
        )

    def test_revoke_user_role(self):
        admin_key = self.login()

        # create a user
        guy_resp = util.execute_http(
            util.pauth_v1beta1_method("CreateUser"),
            key=admin_key,
            body=pauthv1beta1.CreateUserRequest(
                user=pauthv1beta1.User(email="guy@example.com"),
                password="guy-password",
            ),
            response_shape=pauthv1beta1.CreateUserResponse,
        )

        # grant them a role
        util.execute_http(
            util.pauth_v1beta1_method("GrantUserRole"),
            key=admin_key,
            body=pauthv1beta1.GrantUserRoleRequest(
                user_id=unwrap(guy_resp.user).id,
                role="some-role",
            ),
        )

        # revoke it
        util.execute_http(
            util.pauth_v1beta1_method("RevokeUserRole"),
            key=admin_key,
            body=pauthv1beta1.RevokeUserRoleRequest(
                user_id=unwrap(guy_resp.user).id,
                role="some-role",
            ),
        )

        # read the user back
        read_resp = self.strip_ids(
            util.execute_http(
                util.pauth_v1beta1_method("ReadUser"),
                key=admin_key,
                body=pauthv1beta1.ReadUserReqeust(
                    user_id=unwrap(guy_resp.user).id,
                ),
                response_shape=pauthv1beta1.ReadUserResponse,
            )
        )
        compare(
            actual=read_resp.user,
            expected=pauthv1beta1.User(
                email="guy@example.com",
            ),
        )

        # list the users
        resp = self.strip_ids(
            util.execute_http(
                util.pauth_v1beta1_method("ListUsers"),
                key=admin_key,
                body=pauthv1beta1.ListUsersRequest(),
                response_shape=pauthv1beta1.ListUsersResponse,
            )
        )

        compare(
            actual=resp.users,
            expected=[
                pauthv1beta1.User(email="admin@example.com", roles=["admin"]),
                pauthv1beta1.User(email="guy@example.com"),
            ],
        )

    def test_list_user_roles(self):
        admin_key = self.login()

        # create a user
        guy_resp = util.execute_http(
            util.pauth_v1beta1_method("CreateUser"),
            key=admin_key,
            body=pauthv1beta1.CreateUserRequest(
                user=pauthv1beta1.User(email="guy@example.com"),
                password="guy-password",
            ),
            response_shape=pauthv1beta1.CreateUserResponse,
        )

        # grant them a role
        util.execute_http(
            util.pauth_v1beta1_method("GrantUserRole"),
            key=admin_key,
            body=pauthv1beta1.GrantUserRoleRequest(
                user_id=unwrap(guy_resp.user).id,
                role="some-role",
            ),
        )

        # list their roles
        role_resp = util.execute_http(
            util.pauth_v1beta1_method("ListUserRoles"),
            key=admin_key,
            body=pauthv1beta1.ListUserRolesRequest(
                user_id=unwrap(guy_resp.user).id,
            ),
            response_shape=pauthv1beta1.ListUserRolesResponse,
        )
        compare(actual=role_resp.roles, expected=["some-role"])

    def test_list_user_roles_self(self):
        admin_key = self.login()

        # list their roles
        role_resp = util.execute_http(
            util.pauth_v1beta1_method("ListUserRoles"),
            key=admin_key,
            body=pauthv1beta1.ListUserRolesRequest(),
            response_shape=pauthv1beta1.ListUserRolesResponse,
        )
        compare(actual=role_resp.roles, expected=["admin"])

    def test_is_active_key(self):
        # active keys should return true
        resp = util.execute_http(
            util.pauth_v1beta1_method("IsKeyActive"),
            body=pauthv1beta1.IsKeyActiveRequest(
                access_key=self.login(),
            ),
            response_shape=pauthv1beta1.IsKeyActiveResponse,
        )
        compare(actual=resp.active, expected=True)

        # unknown keys should be false (which should also catch inactive keys)
        resp = util.execute_http(
            util.pauth_v1beta1_method("IsKeyActive"),
            body=pauthv1beta1.IsKeyActiveRequest(
                access_key="im-a-fake-key",
            ),
            response_shape=pauthv1beta1.IsKeyActiveResponse,
        )
        compare(actual=resp.active, expected=False)
