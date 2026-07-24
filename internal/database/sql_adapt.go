package database

import (
	"fmt"
	"regexp"
	"strings"
)

// Prepare rewrites dialect-specific SQL then rebinds placeholders for the driver.
// Deprecated name: use Adapt. Kept as alias.
func (d Dialect) Prepare(query string) string {
	return d.Adapt(query)
}

// Adapt rewrites dialect-specific SQL then rebinds placeholders for the driver.
func (d Dialect) Adapt(query string) string {
	if !d.IsPostgres() {
		return query
	}
	return d.Rebind(adaptSQLForPostgres(query))
}

var (
	reInsertOrIgnore  = regexp.MustCompile(`(?i)\bINSERT\s+OR\s+IGNORE\s+INTO\b`)
	reInsertOrReplace = regexp.MustCompile(`(?i)\bINSERT\s+OR\s+REPLACE\s+INTO\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]+)\)\s*VALUES`)
	reAutoIncrPK      = regexp.MustCompile(`(?i)\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b`)
	reDatetimeType    = regexp.MustCompile(`(?i)\bDATETIME\b`)
	reRowID           = regexp.MustCompile(`(?i)\browid\b`)
	reStrftimeEpoch   = regexp.MustCompile(`(?i)strftime\s*\(\s*'%s'\s*,\s*([^)]+?)\s*\)`)
	reDatetimeFn      = regexp.MustCompile(`(?i)datetime\s*\(\s*([^)]+?)\s*\)`)
	reDatetimeNowArg  = regexp.MustCompile(`(?i)datetime\s*\(\s*'now'\s*,\s*\?\s*\)`)
	reDatetimeNowLit  = regexp.MustCompile(`(?i)datetime\s*\(\s*'now'\s*,\s*'(-?\d+)\s+days?'\s*\)`)
	reIfNull          = regexp.MustCompile(`(?i)\bIFNULL\s*\(`)
)

// adaptSQLForPostgres converts common SQLite SQL fragments to PostgreSQL.
func adaptSQLForPostgres(query string) string {
	q := query

	// Meta: table existence
	if strings.Contains(strings.ToLower(q), "sqlite_master") {
		q = regexp.MustCompile(`(?is)SELECT\s+COUNT\(\*\)\s+FROM\s+sqlite_master\s+WHERE\s+type\s*=\s*'table'\s+AND\s+name\s*=\s*\?`).
			ReplaceAllString(q, `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = ?`)
		q = regexp.MustCompile(`(?is)SELECT\s+COUNT\(\*\)\s+FROM\s+sqlite_master\s+WHERE\s+type\s*=\s*'table'\s+AND\s+name\s*=\s*'([^']+)'`).
			ReplaceAllString(q, `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = '$1'`)
	}

	// Meta: pragma_table_info('t') WHERE name=?  / pragma_table_info(?) WHERE name=?
	// also: WHERE name='literal'
	if strings.Contains(strings.ToLower(q), "pragma_table_info") {
		q = regexp.MustCompile(`(?is)SELECT\s+COUNT\(\*\)\s+FROM\s+pragma_table_info\(\s*'([^']+)'\s*\)\s+WHERE\s+name\s*=\s*\?`).
			ReplaceAllString(q, `SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = '$1' AND column_name = ?`)
		q = regexp.MustCompile(`(?is)SELECT\s+COUNT\(\*\)\s+FROM\s+pragma_table_info\(\s*\?\s*\)\s+WHERE\s+name\s*=\s*\?`).
			ReplaceAllString(q, `SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ? AND column_name = ?`)
		q = regexp.MustCompile(`(?is)SELECT\s+COUNT\(\*\)\s+FROM\s+pragma_table_info\(\s*'([^']+)'\s*\)\s+WHERE\s+name\s*=\s*'([^']+)'`).
			ReplaceAllString(q, `SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = '$1' AND column_name = '$2'`)
		// bare SELECT ... pragma without COUNT (unlikely)
		q = regexp.MustCompile(`(?is)FROM\s+pragma_table_info\(\s*'([^']+)'\s*\)`).
			ReplaceAllString(q, `FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = '$1' /*pragma_table_info*/`)
	}

	// INSERT OR IGNORE INTO t ... -> INSERT INTO t ... ON CONFLICT DO NOTHING
	if reInsertOrIgnore.MatchString(q) {
		q = reInsertOrIgnore.ReplaceAllString(q, "INSERT INTO")
		q = appendOnConflictDoNothing(q)
	}

	// INSERT OR REPLACE INTO t (a,b,...) VALUES -> INSERT ... ON CONFLICT (a) DO UPDATE SET ...
	if m := reInsertOrReplace.FindStringSubmatchIndex(q); m != nil {
		table := q[m[2]:m[3]]
		colsRaw := q[m[4]:m[5]]
		cols := splitSQLIdentList(colsRaw)
		head := "INSERT INTO " + table + " (" + colsRaw + ") VALUES"
		q = q[:m[0]] + head + q[m[1]:]
		if len(cols) > 0 {
			pk := cols[0]
			var sets []string
			for _, c := range cols[1:] {
				sets = append(sets, c+" = EXCLUDED."+c)
			}
			conflict := " ON CONFLICT (" + pk + ") DO UPDATE SET "
			if len(sets) == 0 {
				conflict = " ON CONFLICT (" + pk + ") DO NOTHING"
			} else {
				conflict += strings.Join(sets, ", ")
			}
			q = appendBeforeTrailingSemicolon(q, conflict)
		}
	}

	// DDL
	q = reAutoIncrPK.ReplaceAllString(q, "BIGSERIAL PRIMARY KEY")

	// Avoid rewriting datetime() function calls: only bare type in DDL-ish contexts is hard.
	// Replace DATETIME type when it appears as a column type (not function): " DATETIME" or "DATETIME,"
	q = rewriteDatetimeType(q)

	// rowid -> ctid (stable physical identity on PG)
	q = reRowID.ReplaceAllString(q, "ctid")

	// strftime('%s', col) -> EXTRACT(EPOCH FROM (col)::timestamptz)
	q = reStrftimeEpoch.ReplaceAllString(q, "EXTRACT(EPOCH FROM ($1)::timestamptz)")

	// datetime('now', ?) with bound "-N days" style arg from Go — convert to interval param
	// Call sites pass "-7 days"; PG needs "7 days" with subtraction. Keep helper paths preferred.
	// Map: datetime('now', ?) -> (NOW() AT TIME ZONE 'utc') + (?::text)::interval
	// where arg should be negative interval text like "-7 days" which works in PG: interval '-7 days'
	q = reDatetimeNowArg.ReplaceAllString(q, "((NOW() AT TIME ZONE 'utc') + (?::text)::interval)")

	// datetime('now','-7 days') literals
	q = reDatetimeNowLit.ReplaceAllStringFunc(q, func(s string) string {
		sm := reDatetimeNowLit.FindStringSubmatch(s)
		if len(sm) < 2 {
			return s
		}
		// sm[1] may include leading minus
		return fmt.Sprintf("((NOW() AT TIME ZONE 'utc') + INTERVAL '%s days')", sm[1])
	})

	// datetime('now') with optional offset already handled; bare datetime('now')
	q = regexp.MustCompile(`(?i)datetime\s*\(\s*'now'\s*\)`).ReplaceAllString(q, "(NOW() AT TIME ZONE 'utc')")

	// datetime(expr) general — after specific now-forms
	q = reDatetimeFn.ReplaceAllStringFunc(q, func(s string) string {
		sm := reDatetimeFn.FindStringSubmatch(s)
		if len(sm) < 2 {
			return s
		}
		inner := strings.TrimSpace(sm[1])
		low := strings.ToLower(inner)
		if strings.Contains(low, "now() at time zone") {
			return s
		}
		if strings.HasPrefix(low, "'now'") {
			// residual datetime('now', ...) not matched above
			return s
		}
		// bind param or column
		if inner == "?" {
			return "(?::timestamptz)"
		}
		return "((" + inner + ")::timestamptz)"
	})

	q = reIfNull.ReplaceAllString(q, "COALESCE(")

	return q
}

func rewriteDatetimeType(q string) string {
	// Replace column type DATETIME with TIMESTAMPTZ; leave datetime( function alone (already lowercased often).
	var b strings.Builder
	b.Grow(len(q))
	i := 0
	for i < len(q) {
		// match DATETIME as whole word when not followed by (
		if i+8 <= len(q) && strings.EqualFold(q[i:i+8], "DATETIME") {
			// word boundary before
			if i > 0 {
				prev := q[i-1]
				if (prev >= 'a' && prev <= 'z') || (prev >= 'A' && prev <= 'Z') || (prev >= '0' && prev <= '9') || prev == '_' {
					b.WriteByte(q[i])
					i++
					continue
				}
			}
			j := i + 8
			// skip spaces
			k := j
			for k < len(q) && (q[k] == ' ' || q[k] == '\t') {
				k++
			}
			if k < len(q) && q[k] == '(' {
				// datetime( function
				b.WriteString(q[i:j])
				i = j
				continue
			}
			b.WriteString("TIMESTAMPTZ")
			i = j
			continue
		}
		b.WriteByte(q[i])
		i++
	}
	return b.String()
}

func splitSQLIdentList(cols string) []string {
	parts := strings.Split(cols, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"'`+"`")
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func appendOnConflictDoNothing(q string) string {
	if strings.Contains(strings.ToUpper(q), "ON CONFLICT") {
		return q
	}
	return appendBeforeTrailingSemicolon(q, " ON CONFLICT DO NOTHING")
}

func appendBeforeTrailingSemicolon(q, suffix string) string {
	trimRight := strings.TrimRight(q, " \t\r\n")
	if strings.HasSuffix(trimRight, ";") {
		return strings.TrimSuffix(trimRight, ";") + suffix + ";"
	}
	return q + suffix
}

// splitSQLStatements splits multi-statement SQL for drivers that disallow batches (pgx).
func splitSQLStatements(query string) []string {
	parts := strings.Split(query, ";")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{strings.TrimSpace(query)}
	}
	return out
}
