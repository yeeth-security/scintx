package store

import (
	"database/sql"
	"fmt"
	"strings"
)

type dialect int

const (
	dialectSQLite dialect = iota
	dialectPostgres
)

// SQLStore persists SCINTX state in SQLite or Postgres via database/sql.
// Domain objects are stored as JSON text for schema flexibility.
type SQLStore struct {
	db      *sql.DB
	dialect dialect
}

func (s *SQLStore) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// q rebinds ? placeholders to $1,$2,... for Postgres.
func (s *SQLStore) q(query string) string {
	if s.dialect == dialectSQLite {
		return query
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			n++
			fmt.Fprintf(&b, "$%d", n)
			continue
		}
		b.WriteByte(query[i])
	}
	return b.String()
}

func (s *SQLStore) migrate() error {
	var stmts []string
	switch s.dialect {
	case dialectSQLite:
		stmts = sqliteSchema
	case dialectPostgres:
		stmts = postgresSchema
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("migrate: %w\nstmt: %s", err, stmt)
		}
	}
	// Additive column for older DBs created before request_hash existed.
	_, _ = s.db.Exec(s.q(`ALTER TABLE idempotency ADD COLUMN request_hash TEXT NOT NULL DEFAULT ''`))
	return nil
}

var sqliteSchema = []string{
	`CREATE TABLE IF NOT EXISTS submissions (
		id TEXT PRIMARY KEY,
		body TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS idempotency (
		key TEXT PRIMARY KEY,
		submission_id TEXT NOT NULL,
		request_hash TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE TABLE IF NOT EXISTS results (
		id TEXT PRIMARY KEY,
		submission_id TEXT NOT NULL,
		body TEXT NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS idx_results_submission ON results(submission_id)`,
	`CREATE TABLE IF NOT EXISTS decisions (
		id TEXT PRIMARY KEY,
		body TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		body TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS artifacts (
		digest TEXT PRIMARY KEY,
		content BLOB NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS providers (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		capabilities TEXT NOT NULL,
		sort_order INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE TABLE IF NOT EXISTS jobs (
		submission_id TEXT PRIMARY KEY,
		status TEXT NOT NULL,
		created_at TEXT NOT NULL,
		lease_owner TEXT,
		lease_until TEXT,
		attempts INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX IF NOT EXISTS idx_jobs_pending ON jobs(status, created_at)`,
	// merged_results stores one cross-provider aggregated result per submission.
	`CREATE TABLE IF NOT EXISTS merged_results (
		submission_id TEXT PRIMARY KEY,
		body TEXT NOT NULL
	)`,
}

var postgresSchema = []string{
	`CREATE TABLE IF NOT EXISTS submissions (
		id TEXT PRIMARY KEY,
		body TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS idempotency (
		key TEXT PRIMARY KEY,
		submission_id TEXT NOT NULL,
		request_hash TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE TABLE IF NOT EXISTS results (
		id TEXT PRIMARY KEY,
		submission_id TEXT NOT NULL,
		body TEXT NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS idx_results_submission ON results(submission_id)`,
	`CREATE TABLE IF NOT EXISTS decisions (
		id TEXT PRIMARY KEY,
		body TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS events (
		id BIGSERIAL PRIMARY KEY,
		body TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS artifacts (
		digest TEXT PRIMARY KEY,
		content BYTEA NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS providers (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		capabilities TEXT NOT NULL,
		sort_order INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE TABLE IF NOT EXISTS jobs (
		submission_id TEXT PRIMARY KEY,
		status TEXT NOT NULL,
		created_at TEXT NOT NULL,
		lease_owner TEXT,
		lease_until TEXT,
		attempts INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX IF NOT EXISTS idx_jobs_pending ON jobs(status, created_at)`,
	// merged_results stores one cross-provider aggregated result per submission.
	`CREATE TABLE IF NOT EXISTS merged_results (
		submission_id TEXT PRIMARY KEY,
		body TEXT NOT NULL
	)`,
}
