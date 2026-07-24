package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cyberstrike-ai/internal/config"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
)

// OpenOptions configures a database open (session or knowledge).
type OpenOptions struct {
	Dialect Dialect
	// SQLite path (file). Required when Dialect is sqlite.
	Path string
	// Postgres DSN (postgres://... or key=value). Required when Dialect is postgres (or use BuildPostgresDSN fields).
	DSN      string
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string

	// ArtifactsBaseDir: parent for conversation_artifacts; empty uses dir(Path) or cwd/data.
	ArtifactsBaseDir string
	// SkipInit skips initTables / initKnowledgeTables.
	SkipInit bool
	// KnowledgeOnly only creates knowledge tables (NewKnowledgeDB).
	KnowledgeOnly bool
	Logger        *zap.Logger
}

// OpenFromConfig opens the main session database from config.
func OpenFromConfig(cfg config.DatabaseConfig, logger *zap.Logger) (*DB, error) {
	d := normalizeDialect(cfg.Driver)
	opt := OpenOptions{
		Dialect:  d,
		Path:     cfg.Path,
		DSN:      cfg.DSN,
		Host:     cfg.Host,
		Port:     cfg.Port,
		User:     cfg.User,
		Password: cfg.Password,
		DBName:   cfg.DBName,
		SSLMode:  cfg.SSLMode,
		Logger:   logger,
	}
	if d.IsSQLite() {
		if strings.TrimSpace(opt.Path) == "" {
			opt.Path = "data/conversations.db"
		}
		opt.ArtifactsBaseDir = filepath.Dir(opt.Path)
	} else {
		opt.ArtifactsBaseDir = "data"
	}
	return Open(opt)
}

// OpenKnowledgeFromConfig opens the knowledge database (or returns nil path meaning "use session DB").
// When knowledge uses the same postgres DSN and KnowledgeDBName is set, connects to that database name.
func OpenKnowledgeFromConfig(cfg config.DatabaseConfig, logger *zap.Logger) (*DB, error) {
	d := normalizeDialect(cfg.Driver)
	if d.IsSQLite() {
		path := strings.TrimSpace(cfg.KnowledgeDBPath)
		if path == "" {
			return nil, fmt.Errorf("knowledge_db_path 为空")
		}
		return Open(OpenOptions{
			Dialect:       DialectSQLite,
			Path:          path,
			KnowledgeOnly: true,
			Logger:        logger,
		})
	}

	// Postgres: prefer knowledge_dsn; else same cluster + knowledge_dbname; else same DSN (shared DB, knowledge tables only init).
	opt := OpenOptions{
		Dialect:       DialectPostgres,
		DSN:           strings.TrimSpace(cfg.KnowledgeDSN),
		Host:          cfg.Host,
		Port:          cfg.Port,
		User:          cfg.User,
		Password:      cfg.Password,
		SSLMode:       cfg.SSLMode,
		KnowledgeOnly: true,
		Logger:        logger,
	}
	if opt.DSN == "" {
		if name := strings.TrimSpace(cfg.KnowledgeDBName); name != "" {
			opt.DBName = name
		} else if strings.TrimSpace(cfg.DSN) != "" {
			opt.DSN = cfg.DSN
		} else {
			opt.DBName = cfg.DBName
		}
	}
	return Open(opt)
}

// Open opens a database with the given options and runs schema init.
func Open(opt OpenOptions) (*DB, error) {
	d := normalizeDialect(string(opt.Dialect))
	if d != DialectSQLite && d != DialectPostgres {
		return nil, fmt.Errorf("不支持的 database.driver: %s（支持 sqlite | postgres）", opt.Dialect)
	}
	logger := opt.Logger

	var (
		sqlDB *sql.DB
		err   error
	)

	switch d {
	case DialectPostgres:
		dsn, derr := BuildPostgresDSN(opt.DSN, opt.Host, opt.Port, opt.User, opt.Password, opt.DBName, opt.SSLMode)
		if derr != nil {
			return nil, derr
		}
		sqlDB, err = sql.Open("pgx", dsn)
		if err != nil {
			return nil, fmt.Errorf("打开 PostgreSQL 失败: %w", err)
		}
		configurePostgresPool(sqlDB)
	default:
		path := strings.TrimSpace(opt.Path)
		if path == "" {
			return nil, fmt.Errorf("database.path 不能为空（sqlite）")
		}
		if mkErr := os.MkdirAll(filepath.Dir(path), 0o755); mkErr != nil {
			return nil, fmt.Errorf("创建数据库目录失败: %w", mkErr)
		}
		sqlDB, err = sql.Open("sqlite3", path+"?_journal_mode=WAL&_foreign_keys=1&_busy_timeout=5000&_synchronous=NORMAL")
		if err != nil {
			return nil, fmt.Errorf("打开数据库失败: %w", err)
		}
		configureDBPool(sqlDB)
	}

	if err := sqlDB.Ping(); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("连接数据库失败: %w", err)
	}

	if d.IsSQLite() {
		if err := configureSQLitePragmas(sqlDB); err != nil {
			_ = sqlDB.Close()
			return nil, fmt.Errorf("配置数据库 PRAGMA 失败: %w", err)
		}
	}

	database := &DB{
		DB:      sqlDB,
		dialect: d,
		logger:  logger,
	}

	baseDir := strings.TrimSpace(opt.ArtifactsBaseDir)
	if baseDir == "" && d.IsSQLite() {
		baseDir = filepath.Dir(opt.Path)
	}
	if baseDir == "" {
		baseDir = "data"
	}
	artDir := filepath.Join(baseDir, "conversation_artifacts")
	if mkErr := os.MkdirAll(artDir, 0o755); mkErr == nil {
		database.conversationArtifactsDir = artDir
	} else if logger != nil {
		logger.Warn("创建 conversation artifacts 目录失败", zap.String("dir", artDir), zap.Error(mkErr))
	}

	if !opt.SkipInit {
		if opt.KnowledgeOnly {
			if err := database.initKnowledgeTables(); err != nil {
				_ = sqlDB.Close()
				return nil, fmt.Errorf("初始化知识库表失败: %w", err)
			}
		} else {
			if err := database.initTables(); err != nil {
				_ = sqlDB.Close()
				return nil, fmt.Errorf("初始化表失败: %w", err)
			}
		}
	}

	if d.IsSQLite() {
		name := "conversations"
		if opt.KnowledgeOnly {
			name = "knowledge"
		}
		database.startPassiveCheckpointLoop(name)
	}

	if logger != nil {
		logger.Info("数据库已连接",
			zap.String("driver", string(d)),
			zap.Bool("knowledge_only", opt.KnowledgeOnly),
		)
	}
	return database, nil
}

func configurePostgresPool(db *sql.DB) {
	db.SetMaxOpenConns(50)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)
}

// Dialect returns the SQL dialect for this handle.
func (db *DB) Dialect() Dialect {
	if db == nil {
		return DialectSQLite
	}
	if db.dialect == "" {
		return DialectSQLite
	}
	return db.dialect
}

// IsPostgres reports whether this handle is PostgreSQL.
func (db *DB) IsPostgres() bool { return db.Dialect().IsPostgres() }

// Prepare adapts and rebinds a query for this handle (SQL string only).
func (db *DB) Prepare(query string) string {
	return db.Dialect().Adapt(query)
}

// Adapt is an alias of Prepare for clarity.
func (db *DB) Adapt(query string) string {
	return db.Dialect().Adapt(query)
}

// Exec executes a query with dialect adaptation.
func (db *DB) Exec(query string, args ...interface{}) (sql.Result, error) {
	return db.ExecContext(context.Background(), query, args...)
}

// ExecContext executes a query with dialect adaptation.
func (db *DB) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	d := db.Dialect()
	if d.IsPostgres() {
		stmts := splitSQLStatements(query)
		if len(stmts) > 1 {
			var res sql.Result
			var err error
			for i, s := range stmts {
				a := args
				if i > 0 {
					a = nil
				}
				res, err = db.DB.ExecContext(ctx, d.Adapt(s), a...)
				if err != nil {
					return res, err
				}
			}
			return res, nil
		}
	}
	return db.DB.ExecContext(ctx, d.Adapt(query), args...)
}

// Query runs a query with dialect adaptation.
func (db *DB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return db.QueryContext(context.Background(), query, args...)
}

// QueryContext runs a query with dialect adaptation.
func (db *DB) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	return db.DB.QueryContext(ctx, db.Adapt(query), args...)
}

// QueryRow runs a query with dialect adaptation.
func (db *DB) QueryRow(query string, args ...interface{}) *sql.Row {
	return db.QueryRowContext(context.Background(), query, args...)
}

// QueryRowContext runs a query with dialect adaptation.
func (db *DB) QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	return db.DB.QueryRowContext(ctx, db.Adapt(query), args...)
}

// Tx is a dialect-aware transaction.
type Tx struct {
	*sql.Tx
	dialect Dialect
}

// Begin starts a dialect-aware transaction.
func (db *DB) Begin() (*Tx, error) {
	return db.BeginTx(context.Background(), nil)
}

// BeginTx starts a dialect-aware transaction with options.
func (db *DB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*Tx, error) {
	tx, err := db.DB.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &Tx{Tx: tx, dialect: db.Dialect()}, nil
}

func (tx *Tx) Adapt(query string) string {
	if tx == nil {
		return query
	}
	return tx.dialect.Adapt(query)
}

// Prepare prepares a statement with dialect adaptation (returns *sql.Stmt).
func (tx *Tx) Prepare(query string) (*sql.Stmt, error) {
	return tx.Tx.Prepare(tx.Adapt(query))
}

// PrepareContext prepares a statement with dialect adaptation.
func (tx *Tx) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	return tx.Tx.PrepareContext(ctx, tx.Adapt(query))
}

func (tx *Tx) Exec(query string, args ...interface{}) (sql.Result, error) {
	return tx.ExecContext(context.Background(), query, args...)
}

func (tx *Tx) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	d := tx.dialect
	if d.IsPostgres() {
		stmts := splitSQLStatements(query)
		if len(stmts) > 1 {
			var res sql.Result
			var err error
			for i, s := range stmts {
				a := args
				if i > 0 {
					a = nil
				}
				res, err = tx.Tx.ExecContext(ctx, d.Adapt(s), a...)
				if err != nil {
					return res, err
				}
			}
			return res, nil
		}
	}
	return tx.Tx.ExecContext(ctx, tx.Adapt(query), args...)
}

func (tx *Tx) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return tx.QueryContext(context.Background(), query, args...)
}

func (tx *Tx) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	return tx.Tx.QueryContext(ctx, tx.Adapt(query), args...)
}

func (tx *Tx) QueryRow(query string, args ...interface{}) *sql.Row {
	return tx.QueryRowContext(context.Background(), query, args...)
}

func (tx *Tx) QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	return tx.Tx.QueryRowContext(ctx, tx.Adapt(query), args...)
}

// tableExists reports whether a table exists in the current schema.
func (db *DB) tableExists(name string) (bool, error) {
	var n int
	err := db.QueryRow(db.Dialect().tableExistsSQL(), name).Scan(&n)
	return n > 0, err
}

// columnExists reports whether a column exists on a table.
func (db *DB) columnExists(table, column string) (bool, error) {
	var n int
	err := db.QueryRow(db.Dialect().columnExistsSQL(), table, column).Scan(&n)
	return n > 0, err
}
