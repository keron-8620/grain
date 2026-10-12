package db

import (
	"context"
	"os"
	"strings"

	"emperror.dev/errors"
	"gorm.io/gorm"
)

// ExecSQLFile executes an SQL script file, supporting all databases and comment types
func ExecSQLFile(ctx context.Context, db *gorm.DB, filePath string) error {
	if db == nil {
		return errors.New("database instance is nil")
	}

	// Read SQL file
	content, readErr := os.ReadFile(filePath) // #nosec G304
	if readErr != nil {
		return errors.WithMessagef(readErr, "failed to read SQL file, path: %s", filePath)
	}

	// Core: clean all comments (// -- # /* */)
	sqlClean := cleanSQLComments(string(content))
	// Split statements by semicolon
	sqlList := splitSQL(sqlClean)

	return WithTransaction(ctx, db, func(tx *gorm.DB) error {
		// Execute statement by statement
		for _, sql := range sqlList {
			if sql == "" {
				continue
			}
			// Execute SQL using transaction object to ensure all operations are in the same transaction
			if execErr := tx.Exec(sql).Error; execErr != nil {
				return errors.Wrap(execErr, "failed to execute SQL statement")
			}
		}
		return nil
	})
}

// matchDollarQuote checks whether a PostgreSQL dollar-quote delimiter starts at sql[i].
// A valid dollar-quote delimiter is either "$$" (empty tag) or "$tag$" where tag begins with
// [a-zA-Z_] and contains only [a-zA-Z0-9_].
// Returns the matched delimiter string (e.g., "$$" or "$tag$") and true, or empty string and false.
func matchDollarQuote(sql string, i int) (string, bool) {
	n := len(sql)
	if i >= n || sql[i] != '$' {
		return "", false
	}
	// Case 1: $$
	if i+1 < n && sql[i+1] == '$' {
		return "$$", true
	}
	// Case 2: $tag$
	if i+1 >= n {
		return "", false
	}
	first := sql[i+1]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || first == '_') {
		return "", false
	}
	for j := i + 2; j < n; j++ {
		ch := sql[j]
		if ch == '$' {
			return sql[i : j+1], true
		}
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_') {
			return "", false
		}
	}
	return "", false
}

// Safe version: only strips comments outside single quotes and dollar quotes ($$...$$ / $tag$...$tag$),
// without corrupting string content or stored procedure bodies.
// Correctly handles escaped quotes ('' and \').
func cleanSQLComments(sql string) string {
	var result strings.Builder
	n := len(sql)
	inQuote := false // Whether inside a ' string
	dollarTag := ""  // Current active PostgreSQL dollar-quote delimiter

	for i := 0; i < n; {
		// Inside PostgreSQL dollar-quoted string ($$ or $tag$)
		if dollarTag != "" {
			if strings.HasPrefix(sql[i:], dollarTag) {
				result.WriteString(dollarTag)
				i += len(dollarTag)
				dollarTag = ""
				continue
			}
			result.WriteByte(sql[i])
			i++
			continue
		}

		if inQuote {
			// Escaped backslash or escaped character like \' or \\
			if sql[i] == '\\' && i+1 < n {
				result.WriteByte(sql[i])
				result.WriteByte(sql[i+1])
				i += 2
				continue
			}
			// Single quote inside string
			if sql[i] == '\'' {
				// Check for SQL standard escaped quote ''
				if i+1 < n && sql[i+1] == '\'' {
					result.WriteByte('\'')
					result.WriteByte('\'')
					i += 2
					continue
				}
				// Terminating quote
				inQuote = false
				result.WriteByte('\'')
				i++
				continue
			}
			result.WriteByte(sql[i])
			i++
			continue
		}

		// Not in quote
		if sql[i] == '\'' {
			inQuote = true
			result.WriteByte('\'')
			i++
			continue
		}

		// PostgreSQL dollar quote check ($$ or $tag$)
		if tag, ok := matchDollarQuote(sql, i); ok {
			dollarTag = tag
			result.WriteString(tag)
			i += len(tag)
			continue
		}

		// Multi-line comment /*
		if i+1 < n && sql[i] == '/' && sql[i+1] == '*' {
			// Skip until */
			for i += 2; i+1 < n; i++ {
				if sql[i] == '*' && sql[i+1] == '/' {
					i += 2
					break
				}
			}
			continue
		}

		// Single-line comment --  //  #
		if i+1 < n && ((sql[i] == '-' && sql[i+1] == '-') || (sql[i] == '/' && sql[i+1] == '/')) {
			// Skip remainder of this line
			for i < n && sql[i] != '\n' {
				i++
			}
			continue
		}
		if sql[i] == '#' {
			for i < n && sql[i] != '\n' {
				i++
			}
			continue
		}

		// Normal character
		result.WriteByte(sql[i])
		i++
	}

	return strings.TrimSpace(result.String())
}

// splitSQL splits SQL by ;, properly ignoring semicolons inside single quotes and dollar quotes.
func splitSQL(sql string) []string {
	var statements []string
	var current strings.Builder
	n := len(sql)
	inQuote := false
	dollarTag := ""

	for i := 0; i < n; {
		// Inside PostgreSQL dollar-quoted string ($$ or $tag$)
		if dollarTag != "" {
			if strings.HasPrefix(sql[i:], dollarTag) {
				current.WriteString(dollarTag)
				i += len(dollarTag)
				dollarTag = ""
				continue
			}
			current.WriteByte(sql[i])
			i++
			continue
		}

		if inQuote {
			if sql[i] == '\\' && i+1 < n {
				current.WriteByte(sql[i])
				current.WriteByte(sql[i+1])
				i += 2
				continue
			}
			if sql[i] == '\'' {
				if i+1 < n && sql[i+1] == '\'' {
					current.WriteByte('\'')
					current.WriteByte('\'')
					i += 2
					continue
				}
				inQuote = false
				current.WriteByte('\'')
				i++
				continue
			}
			current.WriteByte(sql[i])
			i++
			continue
		}

		// Not in quote
		if sql[i] == '\'' {
			inQuote = true
			current.WriteByte('\'')
			i++
			continue
		}

		// PostgreSQL dollar quote check ($$ or $tag$)
		if tag, ok := matchDollarQuote(sql, i); ok {
			dollarTag = tag
			current.WriteString(tag)
			i += len(tag)
			continue
		}

		if sql[i] == ';' {
			stmt := strings.TrimSpace(current.String())
			if stmt != "" {
				statements = append(statements, stmt)
			}
			current.Reset()
			i++
			continue
		}

		current.WriteByte(sql[i])
		i++
	}

	// Last statement
	stmt := strings.TrimSpace(current.String())
	if stmt != "" {
		statements = append(statements, stmt)
	}

	return statements
}
