package db

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"emperror.dev/errors"
	"gorm.io/gorm"
)

// ExecSQLFile executes an SQL script file, supporting all databases and comment types
func ExecSQLFile(ctx context.Context, db *gorm.DB, filePath string) error {
	if db == nil {
		return errors.New("database instance is nil")
	}
	if err := contextError(ctx); err != nil {
		return err
	}

	// Read SQL file
	content, readErr := os.ReadFile(filepath.Clean(filePath)) // #nosec G304
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
			if err := contextError(ctx); err != nil {
				return err
			}
			// Execute SQL using transaction object to ensure all operations are in the same transaction
			if execErr := tx.Exec(sql).Error; execErr != nil {
				return errors.Wrap(MapError(execErr), "failed to execute SQL statement")
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

func isQuoteDelimiter(ch byte) bool {
	return ch == '\'' || ch == '"' || ch == '`'
}

// Safe version: only strips comments outside quoted strings/identifiers ('...', "...", `...`)
// and dollar quotes ($$...$$ / $tag$...$tag$), without corrupting string content, identifiers,
// or stored procedure bodies. Correctly handles escaped quotes (doubled or backslash-escaped).
func cleanSQLComments(sql string) string {
	var result strings.Builder
	n := len(sql)
	var quoteChar byte // Current active quote delimiter (' or " or `), 0 when not in quote
	dollarTag := ""    // Current active PostgreSQL dollar-quote delimiter

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

		if quoteChar != 0 {
			// Escaped backslash or escaped character like \' \" \` or \\
			if sql[i] == '\\' && i+1 < n {
				result.WriteByte(sql[i])
				result.WriteByte(sql[i+1])
				i += 2
				continue
			}
			// Matching quote character inside quoted region
			if sql[i] == quoteChar {
				// Check for SQL standard doubled quote ('' or "" or ``)
				if i+1 < n && sql[i+1] == quoteChar {
					result.WriteByte(quoteChar)
					result.WriteByte(quoteChar)
					i += 2
					continue
				}
				// Terminating quote
				result.WriteByte(quoteChar)
				quoteChar = 0
				i++
				continue
			}
			result.WriteByte(sql[i])
			i++
			continue
		}

		// Not in quote
		if isQuoteDelimiter(sql[i]) {
			quoteChar = sql[i]
			result.WriteByte(sql[i])
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
			closed := false
			for i += 2; i+1 < n; i++ {
				if sql[i] == '*' && sql[i+1] == '/' {
					i += 2
					closed = true
					break
				}
			}
			if !closed {
				i = n
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

// splitSQL splits SQL by ;, properly ignoring semicolons inside quotes ('...', "...", `...`) and dollar quotes.
func splitSQL(sql string) []string {
	var statements []string
	var current strings.Builder
	n := len(sql)
	var quoteChar byte
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

		if quoteChar != 0 {
			if sql[i] == '\\' && i+1 < n {
				current.WriteByte(sql[i])
				current.WriteByte(sql[i+1])
				i += 2
				continue
			}
			if sql[i] == quoteChar {
				if i+1 < n && sql[i+1] == quoteChar {
					current.WriteByte(quoteChar)
					current.WriteByte(quoteChar)
					i += 2
					continue
				}
				current.WriteByte(quoteChar)
				quoteChar = 0
				i++
				continue
			}
			current.WriteByte(sql[i])
			i++
			continue
		}

		// Not in quote
		if isQuoteDelimiter(sql[i]) {
			quoteChar = sql[i]
			current.WriteByte(sql[i])
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
