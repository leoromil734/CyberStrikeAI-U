package database

import (
	"fmt"
	"net/url"
	"strings"
)

// Dialect is the SQL dialect for a DB handle (sqlite | postgres).
type Dialect string

const (
	DialectSQLite   Dialect = "sqlite"
	DialectPostgres Dialect = "postgres"
)

func normalizeDialect(raw string) Dialect {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "sqlite", "sqlite3":
		return DialectSQLite
	case "postgres", "postgresql", "pg":
		return DialectPostgres
	default:
		return Dialect(strings.ToLower(strings.TrimSpace(raw)))
	}
}

// IsPostgres reports whether d is PostgreSQL.
func (d Dialect) IsPostgres() bool { return d == DialectPostgres }

// IsSQLite reports whether d is SQLite.
func (d Dialect) IsSQLite() bool { return d == DialectSQLite || d == "" }

// Rebind converts "?" placeholders to "$1,$2,..." for PostgreSQL.
// SQLite keeps "?" unchanged. Does not rewrite string literals that contain "?".
func (d Dialect) Rebind(query string) string {
	if !d.IsPostgres() {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 16)
	n := 0
	inSingle := false
	for i := 0; i < len(query); i++ {
		c := query[i]
		if c == '\'' {
			// SQL escape: '' inside a string
			if inSingle && i+1 < len(query) && query[i+1] == '\'' {
				b.WriteByte(c)
				b.WriteByte(query[i+1])
				i++
				continue
			}
			inSingle = !inSingle
			b.WriteByte(c)
			continue
		}
		if c == '?' && !inSingle {
			n++
			b.WriteByte('$')
			b.WriteString(fmt.Sprintf("%d", n))
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// UpsertIgnorePrefix is INSERT OR IGNORE / ON CONFLICT DO NOTHING head (without table).
// Prefer full helpers insertOrIgnore / insertOrReplace for complete statements.
func (d Dialect) insertOrIgnoreSQL(tableColsValues string) string {
	// tableColsValues example: "INTO t (a,b) VALUES (?,?)"
	if d.IsPostgres() {
		return "INSERT " + tableColsValues + " ON CONFLICT DO NOTHING"
	}
	return "INSERT OR IGNORE " + tableColsValues
}

func (d Dialect) insertOrReplaceSQL(tableColsValues string) string {
	// Prefer explicit ON CONFLICT for Postgres; SQLite keeps INSERT OR REPLACE.
	if d.IsPostgres() {
		// Caller should use ON CONFLICT(...) DO UPDATE when possible.
		// Fallback: plain INSERT (may fail on conflict).
		return "INSERT " + tableColsValues
	}
	return "INSERT OR REPLACE " + tableColsValues
}

// boolIntExpr maps boolean-ish INTEGER columns for both dialects (0/1 stored as int).
// Not used for true PG BOOLEAN columns.

// epochCompareSQL compares a DATETIME/TEXT timestamp column to a bound RFC3339 param as Unix seconds.
func (d Dialect) epochCompareSQL(column, op string) string {
	if d.IsPostgres() {
		// column may be timestamptz or text-compatible; cast via ::timestamptz when needed
		return fmt.Sprintf("EXTRACT(EPOCH FROM (%s)::timestamptz) %s EXTRACT(EPOCH FROM (?::timestamptz))", column, op)
	}
	return "strftime('%s', " + column + ") " + op + " strftime('%s', ?)"
}

// durationMsSQL returns SQL for duration in milliseconds between endExpr and startExpr (end - start).
// endExpr/startExpr may be column names or placeholders ("?").
// SQLite: julianday; PostgreSQL: EXTRACT(EPOCH). Both clamp negative to 0.
func (d Dialect) durationMsSQL(endExpr, startExpr string) string {
	if d.IsPostgres() {
		return fmt.Sprintf(
			"GREATEST(0, CAST(ROUND(EXTRACT(EPOCH FROM ((%s)::timestamptz - (%s)::timestamptz)) * 1000) AS BIGINT))",
			endExpr, startExpr,
		)
	}
	return fmt.Sprintf(
		"MAX(0, CAST((julianday(%s) - julianday(%s)) * 86400000 AS INTEGER))",
		endExpr, startExpr,
	)
}

// datetimeLT compares COALESCE timestamps against a bound cutoff (RFC3339 string).
func (d Dialect) datetimeLT(expr string) string {
	if d.IsPostgres() {
		return fmt.Sprintf("(%s)::timestamptz < (?::timestamptz)", expr)
	}
	return fmt.Sprintf("datetime(%s) < datetime(?)", expr)
}

// nowMinusIntervalSQL returns a SQL fragment for "now - N days" as a bound param style.
// For SQLite: datetime('now', ?) with arg "-N days"
// For Postgres: (NOW() AT TIME ZONE 'utc') - (?::text)::interval with arg "N days"
func (d Dialect) recentWithinDays(column string, days int) (sql string, arg interface{}) {
	if d.IsPostgres() {
		return fmt.Sprintf("(%s)::timestamptz >= (NOW() AT TIME ZONE 'utc') - (?::text)::interval", column),
			fmt.Sprintf("%d days", days)
	}
	return fmt.Sprintf("datetime(%s) >= datetime('now', ?)", column), fmt.Sprintf("-%d days", days)
}

func (d Dialect) olderThanDays(column string, days int) (sql string, arg interface{}) {
	if d.IsPostgres() {
		return fmt.Sprintf("(%s)::timestamptz < (NOW() AT TIME ZONE 'utc') - (?::text)::interval", column),
			fmt.Sprintf("%d days", days)
	}
	return fmt.Sprintf("datetime(%s) < datetime('now', ?)", column), fmt.Sprintf("-%d days", days)
}

func (d Dialect) sinceDaysAgo(column string, days int) (sql string, arg interface{}) {
	// first_seen_at >= now-(days-1)
	if d.IsPostgres() {
		return fmt.Sprintf("(%s)::timestamptz >= (NOW() AT TIME ZONE 'utc') - (?::text)::interval", column),
			fmt.Sprintf("%d days", days)
	}
	return fmt.Sprintf("datetime(%s) >= datetime('now', ?)", column), fmt.Sprintf("-%d days", days)
}

func (d Dialect) dateTrunc(column string) string {
	if d.IsPostgres() {
		return fmt.Sprintf("((%s)::timestamptz AT TIME ZONE 'utc')::date", column)
	}
	return fmt.Sprintf("date(%s)", column)
}

// serialPK is INTEGER PRIMARY KEY AUTOINCREMENT / BIGSERIAL PRIMARY KEY.
func (d Dialect) serialPK() string {
	if d.IsPostgres() {
		return "BIGSERIAL PRIMARY KEY"
	}
	return "INTEGER PRIMARY KEY AUTOINCREMENT"
}

// orderByStable appends a stable secondary key (rowid / ctid).
func (d Dialect) orderByStable(primary string) string {
	if d.IsPostgres() {
		return primary + ", ctid ASC"
	}
	return primary + ", rowid ASC"
}

// tableExistsSQL returns a query that scans COUNT(*) into an int for table existence.
func (d Dialect) tableExistsSQL() string {
	if d.IsPostgres() {
		return `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = ?`
	}
	return `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`
}

// columnExistsSQL returns a query that scans COUNT(*) for a column on a table.
func (d Dialect) columnExistsSQL() string {
	if d.IsPostgres() {
		return `SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ? AND column_name = ?`
	}
	// SQLite: pragma_table_info is a table-valued function; table name as bind works on modern SQLite.
	return `SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?`
}

// columnExistsFixedTableSQL for migrations that used pragma_table_info('table').
func (d Dialect) columnExistsFixedTableSQL(table string) string {
	if d.IsPostgres() {
		return fmt.Sprintf(
			`SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = '%s' AND column_name = ?`,
			strings.ReplaceAll(table, "'", "''"),
		)
	}
	return fmt.Sprintf(`SELECT COUNT(*) FROM pragma_table_info('%s') WHERE name=?`, strings.ReplaceAll(table, "'", "''"))
}

// castPortText for DISTINCT port aggregation.
func (d Dialect) castPortText() string {
	if d.IsPostgres() {
		return "CAST(port AS TEXT)"
	}
	return "CAST(port AS TEXT)"
}

// BuildPostgresDSN builds a libpq/pgx URL from discrete fields or returns dsn as-is.
func BuildPostgresDSN(dsn, host string, port int, user, password, dbname, sslmode string) (string, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn != "" {
		return dsn, nil
	}
	host = strings.TrimSpace(host)
	if host == "" {
		host = "127.0.0.1"
	}
	if port <= 0 {
		port = 5432
	}
	dbname = strings.TrimSpace(dbname)
	if dbname == "" {
		return "", fmt.Errorf("database.dbname 或 database.dsn 不能为空（postgres）")
	}
	if sslmode == "" {
		sslmode = "disable"
	}
	u := url.URL{
		Scheme: "postgres",
		Host:   fmt.Sprintf("%s:%d", host, port),
		Path:   "/" + dbname,
	}
	if strings.TrimSpace(user) != "" {
		if password != "" {
			u.User = url.UserPassword(user, password)
		} else {
			u.User = url.User(user)
		}
	}
	q := url.Values{}
	q.Set("sslmode", sslmode)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
