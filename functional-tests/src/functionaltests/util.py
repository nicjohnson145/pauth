import os
from functools import cache
from unittest import TestCase

import requests
from pauth.pauth import v1beta1 as pauthv1beta1
from testfixtures import compare
from betterproto2 import unwrap


class Base(TestCase):
    ADMIN_EMAIL = "admin@example.com"
    ADMIN_PASSWORD = "admin-password"

    GRANT_ADMIN_ALL = True

    def setUp(self):
        execute_http(
            pauth_v1beta1_method("Purge"),
            body=pauthv1beta1.PurgeRequest(),
        )
        self.grant_admin_all_roles()

    def login(self, email=None, password=None):
        resp = execute_http(
            pauth_v1beta1_method("Login"),
            body=pauthv1beta1.LoginRequest(
                email=email or self.ADMIN_EMAIL,
                password=password or self.ADMIN_PASSWORD,
            ),
            response_shape=pauthv1beta1.LoginResponse,
        )
        return resp.access_key

    def grant_admin_all_roles(self):
        if not self.GRANT_ADMIN_ALL:
            return

        token = self.login()

        # get user id
        read_resp = execute_http(
            pauth_v1beta1_method("ReadUser"),
            key=token,
            body=pauthv1beta1.ReadUserReqeust(),
            response_shape=pauthv1beta1.ReadUserResponse,
        )

        roles = [
            "book-uploader",
            "book-updater",
            "shelf-admin",
            "view-only",
        ]
        for role in roles:
            execute_http(
                pauth_v1beta1_method("GrantUserRole"),
                key=token,
                body=pauthv1beta1.GrantUserRoleRequest(
                    user_id=unwrap(read_resp.user).id,
                    role=role,
                ),
            )


def execute_http(path, body=None, key=None, expected_status=200, response_shape=None, error_contains=None):
    args = [path]
    kwargs = {}

    if body is not None:
        kwargs["json"] = body.to_dict() if not isinstance(body, dict) else body

    if key is not None:
        kwargs.setdefault("headers", {})
        kwargs["headers"]["Authorization"] = key

    resp = requests.post(*args, **kwargs)
    msg = compare(actual=resp.status_code, expected=expected_status, raises=False)
    if msg is not None:
        print(resp.text)
        raise AssertionError(msg)

    if expected_status != 200 and error_contains is not None:
        if error_contains not in resp.text:
            print(resp.text)
            raise AssertionError(f"expected to find {error_contains} in error response")

    json = resp.json()
    if response_shape is not None:
        return response_shape.from_dict(json)
    return json


@cache
def pauth_service():
    return os.environ.get("PAUTH_URL", "http://localhost:8080")

def pauth_v1beta1_method(method):
    return f"{pauth_service()}/pauth.v1beta1.PAuthService/{method}"
