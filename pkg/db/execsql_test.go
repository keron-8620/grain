package db

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCleanSQLComments_SingleLineComment(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "remove double slash comment",
			input:    "SELECT * FROM users // this is a comment",
			expected: "SELECT * FROM users",
		},
		{
			name:     "remove dash comment",
			input:    "SELECT * FROM users -- this is a comment",
			expected: "SELECT * FROM users",
		},
		{
			name:     "remove hash comment",
			input:    "SELECT * FROM users # this is a comment",
			expected: "SELECT * FROM users",
		},
		{
			name:     "comment at start",
			input:    "// comment\nSELECT * FROM users",
			expected: "SELECT * FROM users",
		},
		{
			name:     "mixed comments",
			input:    "SELECT * FROM users -- comment1\nSELECT * FROM posts // comment2",
			expected: "SELECT * FROM users \nSELECT * FROM posts",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cleanSQLComments(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestCleanSQLComments_MultiLineComment(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "remove multiline comment",
			input:    "SELECT * FROM /* comment */ users",
			expected: "SELECT * FROM  users",
		},
		{
			name:     "remove nested multiline comment",
			input:    "SELECT /* inner */ * FROM users",
			expected: "SELECT  * FROM users",
		},
		{
			name:     "multiline comment across lines",
			input:    "SELECT * /*\ncomment\n*/ FROM users",
			expected: "SELECT *  FROM users",
		},
		{
			name:     "unclosed multiline comment at end does not leak trailing byte",
			input:    "SELECT * FROM users /* unclosed comment",
			expected: "SELECT * FROM users",
		},
		{
			name:     "unclosed multiline comment with single trailing char",
			input:    "/*x",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cleanSQLComments(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestCleanSQLComments_StringProtection(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "comment inside string should be preserved",
			input:    `SELECT '// not a comment' FROM users`,
			expected: `SELECT '// not a comment' FROM users`,
		},
		{
			name:     "multiline comment inside string",
			input:    `SELECT '/* not a comment */' FROM users`,
			expected: `SELECT '/* not a comment */' FROM users`,
		},
		{
			name:     "mixed string and comment",
			input:    `SELECT 'value --' FROM users -- real comment`,
			expected: `SELECT 'value --' FROM users`,
		},
		{
			name:     "escaped double single quotes with comment marker inside",
			input:    `SELECT 'O''Reilly -- not a comment' FROM users -- real comment`,
			expected: `SELECT 'O''Reilly -- not a comment' FROM users`,
		},
		{
			name:     "backslash escaped single quote with comment marker inside",
			input:    `SELECT 'O\'Reilly // not a comment' FROM users // real comment`,
			expected: `SELECT 'O\'Reilly // not a comment' FROM users`,
		},
		{
			name:     "escaped backslash before quote",
			input:    `SELECT 'path\\''part /* not comment */' FROM users`,
			expected: `SELECT 'path\\''part /* not comment */' FROM users`,
		},
		{
			name:     "untagged dollar quote preserves comments inside",
			input:    "CREATE FUNCTION f() AS $$\n-- comment inside\n/* block inside */\n$$ LANGUAGE plpgsql; -- trailing comment",
			expected: "CREATE FUNCTION f() AS $$\n-- comment inside\n/* block inside */\n$$ LANGUAGE plpgsql;",
		},
		{
			name:     "tagged dollar quote preserves comments inside",
			input:    "CREATE FUNCTION f() AS $func$\n-- comment inside\n$func$ LANGUAGE plpgsql; -- real comment",
			expected: "CREATE FUNCTION f() AS $func$\n-- comment inside\n$func$ LANGUAGE plpgsql;",
		},
		{
			name:     "positional parameters are not treated as dollar quotes",
			input:    "SELECT * FROM users WHERE id = $1 -- real comment",
			expected: "SELECT * FROM users WHERE id = $1",
		},
		{
			name:     "double quoted identifier preserves comment markers and escaped quotes",
			input:    `SELECT "col--1", "col""/*2*/" FROM "tbl#3" -- real comment`,
			expected: `SELECT "col--1", "col""/*2*/" FROM "tbl#3"`,
		},
		{
			name:     "backtick quoted identifier preserves comment markers and escaped backticks",
			input:    "SELECT `col//1`, `col``#2` FROM `tbl--3` # real comment",
			expected: "SELECT `col//1`, `col``#2` FROM `tbl--3`",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cleanSQLComments(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestSplitSQL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "single statement",
			input:    "SELECT * FROM users",
			expected: []string{"SELECT * FROM users"},
		},
		{
			name:     "multiple statements",
			input:    "SELECT * FROM users; SELECT * FROM posts",
			expected: []string{"SELECT * FROM users", "SELECT * FROM posts"},
		},
		{
			name:     "statement with semicolon in string",
			input:    `SELECT ';not a separator' FROM users; SELECT * FROM posts`,
			expected: []string{`SELECT ';not a separator' FROM users`, "SELECT * FROM posts"},
		},
		{
			name:     "statement with escaped double quote containing semicolon",
			input:    `SELECT 'O''Reilly; not a separator' FROM users; SELECT * FROM posts`,
			expected: []string{`SELECT 'O''Reilly; not a separator' FROM users`, "SELECT * FROM posts"},
		},
		{
			name:     "statement with backslash escaped quote containing semicolon",
			input:    `SELECT 'O\'Reilly; not a separator' FROM users; SELECT * FROM posts`,
			expected: []string{`SELECT 'O\'Reilly; not a separator' FROM users`, "SELECT * FROM posts"},
		},
		{
			name:     "untagged dollar quote containing semicolons",
			input:    `CREATE FUNCTION f() AS $$ BEGIN INSERT INTO a VALUES (1); UPDATE b SET x = 2; END; $$; SELECT * FROM posts`,
			expected: []string{`CREATE FUNCTION f() AS $$ BEGIN INSERT INTO a VALUES (1); UPDATE b SET x = 2; END; $$`, "SELECT * FROM posts"},
		},
		{
			name:     "tagged dollar quote containing semicolons",
			input:    `CREATE FUNCTION f() AS $BODY$ BEGIN RETURN 1; END; $BODY$; SELECT * FROM posts`,
			expected: []string{`CREATE FUNCTION f() AS $BODY$ BEGIN RETURN 1; END; $BODY$`, "SELECT * FROM posts"},
		},
		{
			name:     "positional parameter followed by semicolon",
			input:    `SELECT * FROM users WHERE id = $1; SELECT * FROM posts`,
			expected: []string{`SELECT * FROM users WHERE id = $1`, "SELECT * FROM posts"},
		},
		{
			name:     "double quoted identifier containing semicolon and escaped quotes",
			input:    `SELECT "col;1", "col"";2", "col\;3" FROM users; SELECT * FROM posts`,
			expected: []string{`SELECT "col;1", "col"";2", "col\;3" FROM users`, "SELECT * FROM posts"},
		},
		{
			name:     "backtick quoted identifier containing semicolon and escaped backticks",
			input:    "SELECT `col;1`, `col``;2` FROM users; SELECT * FROM posts",
			expected: []string{"SELECT `col;1`, `col``;2` FROM users", "SELECT * FROM posts"},
		},
		{
			name:     "empty statements",
			input:    ";;SELECT * FROM users;;",
			expected: []string{"SELECT * FROM users"},
		},
		{
			name:     "whitespace handling",
			input:    "\nSELECT * FROM users ;\n\nSELECT * FROM posts ; ",
			expected: []string{"SELECT * FROM users", "SELECT * FROM posts"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitSQL(tt.input)
			if len(result) != len(tt.expected) {
				t.Fatalf("expected %d statements, got %d", len(tt.expected), len(result))
			}
			for i, stmt := range result {
				if stmt != tt.expected[i] {
					t.Errorf("statement %d: expected %q, got %q", i, tt.expected[i], stmt)
				}
			}
		})
	}
}

func TestExecSQLFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sql_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	sqlContent := `
CREATE TABLE test_table (
    id INTEGER PRIMARY KEY,
    name TEXT
);
INSERT INTO test_table (name) VALUES ('test');
`
	sqlPath := filepath.Join(tmpDir, "test.sql")
	err = os.WriteFile(sqlPath, []byte(sqlContent), 0644)
	if err != nil {
		t.Fatalf("failed to write SQL file: %v", err)
	}

	c := &DBConf{
		Type:            "sqlite",
		Dsn:             ":memory:",
		MaxIdleConns:    10,
		MaxOpenConns:    100,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: time.Minute * 30,
	}

	gc := NewGormConfig(nil)
	db, err := NewGormDB(c, gc)
	if err != nil {
		t.Fatalf("failed to create test DB: %v", err)
	}
	defer func() { _ = CloseGormDB(db) }()

	ctx := context.Background()
	err = ExecSQLFile(ctx, db, sqlPath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	var count int64
	err = db.Model(&struct{}{}).Table("test_table").Count(&count).Error
	if err != nil {
		t.Fatalf("failed to count records: %v", err)
	}

	if count != 1 {
		t.Errorf("expected 1 record, got %d", count)
	}
}

func TestExecSQLFile_FileNotFound(t *testing.T) {
	c := &DBConf{
		Type:            "sqlite",
		Dsn:             ":memory:",
		MaxIdleConns:    10,
		MaxOpenConns:    100,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: time.Minute * 30,
	}

	gc := NewGormConfig(nil)
	db, err := NewGormDB(c, gc)
	if err != nil {
		t.Fatalf("failed to create test DB: %v", err)
	}
	defer func() { _ = CloseGormDB(db) }()

	ctx := context.Background()
	err = ExecSQLFile(ctx, db, "/nonexistent/path/test.sql")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

func TestExecSQLFile_InvalidSQL(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sql_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	sqlContent := `
INVALID SQL SYNTAX;
`
	sqlPath := filepath.Join(tmpDir, "invalid.sql")
	err = os.WriteFile(sqlPath, []byte(sqlContent), 0644)
	if err != nil {
		t.Fatalf("failed to write SQL file: %v", err)
	}

	c := &DBConf{
		Type:            "sqlite",
		Dsn:             ":memory:",
		MaxIdleConns:    10,
		MaxOpenConns:    100,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: time.Minute * 30,
	}

	gc := NewGormConfig(nil)
	db, err := NewGormDB(c, gc)
	if err != nil {
		t.Fatalf("failed to create test DB: %v", err)
	}
	defer func() { _ = CloseGormDB(db) }()

	ctx := context.Background()
	err = ExecSQLFile(ctx, db, sqlPath)
	if err == nil {
		t.Fatal("expected error for invalid SQL")
	}
}

func TestExecSQLFile_WithComments(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sql_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	sqlContent := `
// This is a comment
CREATE TABLE test_comments (
    id INTEGER PRIMARY KEY -- inline comment
);
/* 
Multi-line comment
*/
INSERT INTO test_comments (id) VALUES (1); # another comment
`
	sqlPath := filepath.Join(tmpDir, "test_with_comments.sql")
	err = os.WriteFile(sqlPath, []byte(sqlContent), 0644)
	if err != nil {
		t.Fatalf("failed to write SQL file: %v", err)
	}

	c := &DBConf{
		Type:            "sqlite",
		Dsn:             ":memory:",
		MaxIdleConns:    10,
		MaxOpenConns:    100,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: time.Minute * 30,
	}

	gc := NewGormConfig(nil)
	db, err := NewGormDB(c, gc)
	if err != nil {
		t.Fatalf("failed to create test DB: %v", err)
	}
	defer func() { _ = CloseGormDB(db) }()

	ctx := context.Background()
	err = ExecSQLFile(ctx, db, sqlPath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	var count int64
	err = db.Model(&struct{}{}).Table("test_comments").Count(&count).Error
	if err != nil {
		t.Fatalf("failed to count records: %v", err)
	}

	if count != 1 {
		t.Errorf("expected 1 record, got %d", count)
	}
}

func TestSplitSQL_EmptyInput(t *testing.T) {
	result := splitSQL("")
	if len(result) != 0 {
		t.Errorf("expected empty result for empty input, got %v", result)
	}
}

func TestSplitSQL_OnlyWhitespace(t *testing.T) {
	result := splitSQL("   \n  ;  \n   ")
	if len(result) != 0 {
		t.Errorf("expected empty result for whitespace only input, got %v", result)
	}
}

func TestCleanSQLComments_EmptyInput(t *testing.T) {
	result := cleanSQLComments("")
	if result != "" {
		t.Errorf("expected empty result for empty input, got %q", result)
	}
}

func TestExecSQLFile_NilDB(t *testing.T) {
	c := &DBConf{
		Type:            "sqlite",
		Dsn:             ":memory:",
		MaxIdleConns:    10,
		MaxOpenConns:    100,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: time.Minute * 30,
	}

	gc := NewGormConfig(nil)
	db, err := NewGormDB(c, gc)
	if err != nil {
		t.Fatalf("failed to create test DB: %v", err)
	}
	defer func() { _ = CloseGormDB(db) }()

	tmpDir, err := os.MkdirTemp("", "sql_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	sqlContent := "SELECT 1;"
	sqlPath := filepath.Join(tmpDir, "test.sql")
	err = os.WriteFile(sqlPath, []byte(sqlContent), 0644)
	if err != nil {
		t.Fatalf("failed to write SQL file: %v", err)
	}

	ctx := context.Background()
	err = ExecSQLFile(ctx, db, sqlPath)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// Real nil DB test
	err = ExecSQLFile(context.Background(), nil, "any.sql")
	if err == nil {
		t.Fatal("expected error for nil db instance")
	}
	if err.Error() != "database instance is nil" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExecSQLFile_RollbackOnFailure(t *testing.T) {
	c := &DBConf{
		Type:            "sqlite",
		Dsn:             ":memory:",
		MaxIdleConns:    10,
		MaxOpenConns:    100,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: time.Minute * 30,
	}

	gc := NewGormConfig(nil)
	db, err := NewGormDB(c, gc)
	if err != nil {
		t.Fatalf("failed to create test DB: %v", err)
	}
	defer func() { _ = CloseGormDB(db) }()

	tmpDir, err := os.MkdirTemp("", "sql_rollback_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// First statement creates table and inserts record, second statement fails syntax.
	// In SQLite (which supports transactional DDL), all changes should roll back.
	sqlContent := `
CREATE TABLE rollback_check (id INTEGER PRIMARY KEY, val TEXT);
INSERT INTO rollback_check (id, val) VALUES (1, 'initial');
SYNTAX ERROR WILL FAIL HERE;
`
	sqlPath := filepath.Join(tmpDir, "fail.sql")
	err = os.WriteFile(sqlPath, []byte(sqlContent), 0644)
	if err != nil {
		t.Fatalf("failed to write SQL file: %v", err)
	}

	ctx := context.Background()
	err = ExecSQLFile(ctx, db, sqlPath)
	if err == nil {
		t.Fatal("expected error for invalid SQL, got nil")
	}

	// Verify rollback_check table does not exist due to transaction rollback
	var count int64
	checkErr := db.Raw("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='rollback_check'").Scan(&count).Error
	if checkErr != nil {
		t.Fatalf("failed to query sqlite_master: %v", checkErr)
	}
	if count != 0 {
		t.Errorf("expected table rollback_check to be rolled back, but found count=%d", count)
	}
}

func TestExecSQLFile_CanceledContext(t *testing.T) {
	c := &DBConf{
		Type: "sqlite",
		Dsn:  ":memory:",
	}
	db, err := NewGormDB(c, NewGormConfig(nil))
	if err != nil {
		t.Fatalf("failed to create test DB: %v", err)
	}
	defer func() { _ = CloseGormDB(db) }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := ExecSQLFile(ctx, db, "nonexistent.sql"); err == nil {
		t.Fatal("expected error for canceled context, got nil")
	}
}
