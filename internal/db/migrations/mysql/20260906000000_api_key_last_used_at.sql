-- +goose Up
-- +goose StatementBegin
ALTER TABLE api_keys
    ADD COLUMN last_used_at TIMESTAMP NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE api_keys
    DROP COLUMN last_used_at;
-- +goose StatementEnd
