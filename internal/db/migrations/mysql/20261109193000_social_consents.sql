-- +goose Up
CREATE TABLE social_consents (
    token VARCHAR(64) PRIMARY KEY,
    expires_at DATETIME(3) NOT NULL,
    INDEX idx_social_consents_expires_at (expires_at)
);

-- +goose Down
DROP TABLE social_consents;
