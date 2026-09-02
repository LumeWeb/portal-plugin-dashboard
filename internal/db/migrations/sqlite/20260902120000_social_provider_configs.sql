-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS social_provider_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME NULL,
    updated_at DATETIME NULL,
    deleted_at DATETIME NULL,
    provider_id VARCHAR(64) NOT NULL,
    display_name VARCHAR(128) NOT NULL,
    client_id VARCHAR(256) NOT NULL,
    client_secret VARCHAR(512) NOT NULL,
    scopes JSON,
    auth_url VARCHAR(512),
    token_url VARCHAR(512),
    user_url VARCHAR(512),
    user_id_key VARCHAR(64),
    user_email_key VARCHAR(64),
    user_name_key VARCHAR(64),
    enabled BOOLEAN DEFAULT FALSE,
    order_index INT DEFAULT 0
);
CREATE UNIQUE INDEX idx_social_provider_configs_provider_id ON social_provider_configs (provider_id);
CREATE INDEX idx_social_provider_configs_deleted_at ON social_provider_configs (deleted_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS social_provider_configs;
-- +goose StatementEnd
