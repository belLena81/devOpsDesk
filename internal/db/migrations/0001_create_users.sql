CREATE TABLE users (
    id            UUID PRIMARY KEY,
    email         TEXT NOT NULL,
    password_hash TEXT,
    github_id     BIGINT,
    github_login  TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT users_email_key UNIQUE (email),
    CONSTRAINT users_github_id_key UNIQUE (github_id),
    CONSTRAINT users_has_login_method CHECK (password_hash IS NOT NULL OR github_id IS NOT NULL)
);
