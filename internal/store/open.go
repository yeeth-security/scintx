package store

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"github.com/yeeth-security/scintx/internal/scintx"

	_ "github.com/jackc/pgx/v5/stdlib" // postgres driver
	_ "modernc.org/sqlite"             // pure-Go sqlite driver
)

// Driver names accepted by Open / SCINTX_STORE.
const (
	DriverMemory   = "memory"
	DriverSQLite   = "sqlite"
	DriverPostgres = "postgres"
)

// Config selects a Store backend.
type Config struct {
	Driver      string // memory | sqlite | postgres
	SQLitePath  string // file path or ":memory:"
	DatabaseURL string // postgres DSN
}

// ConfigFromEnv reads SCINTX_STORE, SCINTX_SQLITE_PATH, SCINTX_DATABASE_URL.
// Empty SCINTX_STORE defaults to memory: ephemeral forwarder mode (no durable DB).
func ConfigFromEnv() Config {
	driver := strings.ToLower(strings.TrimSpace(os.Getenv("SCINTX_STORE")))
	if driver == "" {
		driver = DriverMemory
	}
	sqlitePath := os.Getenv("SCINTX_SQLITE_PATH")
	if sqlitePath == "" {
		sqlitePath = "data/scintx.db"
	}
	return Config{
		Driver:      driver,
		SQLitePath:  sqlitePath,
		DatabaseURL: os.Getenv("SCINTX_DATABASE_URL"),
	}
}

// Open constructs a Store for cfg.
func Open(cfg Config) (scintx.Store, error) {
	switch strings.ToLower(cfg.Driver) {
	case DriverMemory, "":
		return scintx.NewMemoryStore(), nil
	case DriverSQLite, "sqlite3":
		return openSQLite(cfg.SQLitePath)
	case DriverPostgres, "postgresql", "pg":
		if cfg.DatabaseURL == "" {
			return nil, fmt.Errorf("SCINTX_DATABASE_URL is required for postgres store")
		}
		return openPostgres(cfg.DatabaseURL)
	default:
		return nil, fmt.Errorf("unknown SCINTX_STORE %q (want memory|sqlite|postgres)", cfg.Driver)
	}
}

var memorySeq atomic.Uint64

func openSQLite(path string) (*SQLStore, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
			return nil, fmt.Errorf("sqlite mkdir: %w", err)
		}
	}
	// modernc driver name is "sqlite"
	dsn := path
	if path == ":memory:" {
		// Unique name per Open so parallel tests do not share one DB.
		n := memorySeq.Add(1)
		dsn = fmt.Sprintf("file:scintx_mem_%d?mode=memory&cache=shared", n)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite: single writer; limit open conns to avoid lock storms.
	db.SetMaxOpenConns(1)
	s := &SQLStore{db: db, dialect: dialectSQLite}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func openPostgres(url string) (*SQLStore, error) {
	db, err := sql.Open("pgx", url)
	if err != nil {
		return nil, err
	}
	s := &SQLStore{db: db, dialect: dialectPostgres}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func dirOf(path string) string {
	i := strings.LastIndexAny(path, `/\`)
	if i < 0 {
		return "."
	}
	return path[:i]
}
