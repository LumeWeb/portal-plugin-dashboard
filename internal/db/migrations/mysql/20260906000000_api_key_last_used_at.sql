-- +goose Up
-- Guard against environments where the column was already added out-of-band
-- (MySQL has no ADD COLUMN IF NOT EXISTS; works on both MySQL and MariaDB).
SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE table_schema = DATABASE()
      AND table_name = 'api_keys'
      AND column_name = 'last_used_at');
SET @sql = IF(@col_exists = 0,
    'ALTER TABLE api_keys ADD COLUMN last_used_at TIMESTAMP NULL',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- +goose Down
SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE table_schema = DATABASE()
      AND table_name = 'api_keys'
      AND column_name = 'last_used_at');
SET @sql = IF(@col_exists > 0,
    'ALTER TABLE api_keys DROP COLUMN last_used_at',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
