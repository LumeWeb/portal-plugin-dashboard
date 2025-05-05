package mysql

import (
	"embed"
	"io/fs"
)

//go:embed mysql/*.sql
var mysqlFS embed.FS // Embedded MySQL migration files

//go:embed sqlite/*.sql
var sqliteFS embed.FS // Embedded SQLite migration files

// GetMySQL returns the filesystem containing MySQL migration files
// These migrations are used when the plugin is running with a MySQL database
func GetMySQL() fs.FS {
	sub, err := fs.Sub(mysqlFS, "mysql")
	if err != nil {
		panic(err)
	}
	return sub
}

// GetSQLite returns the filesystem containing SQLite migration files
// These migrations are used when the plugin is running with a SQLite database
func GetSQLite() fs.FS {
	sub, err := fs.Sub(sqliteFS, "sqlite")
	if err != nil {
		panic(err)
	}
	return sub
}
