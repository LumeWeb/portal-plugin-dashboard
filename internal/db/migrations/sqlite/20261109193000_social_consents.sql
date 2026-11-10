-- +goose Up
CREATE TABLE social_consents (
    token VARCHAR(64) PRIMARY KEY,
    expires_at DATETIME NOT NULL
);
CREATE INDEX idx_social_consents_expires_at ON social_consents (expires_at);

-- +goose Down
DROP TABLE social_consents;
