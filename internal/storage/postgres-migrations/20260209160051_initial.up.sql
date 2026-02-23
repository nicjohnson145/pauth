BEGIN;

CREATE TABLE pauth_user (
    id        TEXT  NOT NULL,
    email     TEXT          ,
    full_name TEXT          ,
    password  TEXT
);

CREATE TABLE pauth_user_role (
    user_id  TEXT  NOT NULL,
    role     TEXT  NOT NULL
);

CREATE TABLE pauth_user_session (
    id         TEXT                      NOT NULL,
    user_id    TEXT                      NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE  NOT NULL
);

ALTER TABLE
    pauth_user
ADD CONSTRAINT
    pauth_user_pk
PRIMARY KEY (
    id
);

ALTER TABLE
    pauth_user_role
ADD CONSTRAINT
    pauth_user_role_pk
PRIMARY KEY (
    user_id,
    role
);

ALTER TABLE
    pauth_user_session
ADD CONSTRAINT
    pauth_user_session_pk
PRIMARY KEY (
    id
);

ALTER TABLE
    pauth_user_role
ADD CONSTRAINT
    user_id_fk
FOREIGN KEY (
    user_id
)
REFERENCES
    pauth_user(
        id
    )
ON DELETE
    CASCADE
;

ALTER TABLE
    pauth_user_session
ADD CONSTRAINT
    user_id_fk
FOREIGN KEY (
    user_id
)
REFERENCES
    pauth_user(
        id
    )
ON DELETE
    CASCADE
;

COMMIT;
