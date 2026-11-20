package job

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grain/internal/biz/common"
)

func newRemoteExecFixture() *ScriptRecordUseCache {
	return &ScriptRecordUseCache{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestPosixSingleQuote(t *testing.T) {
	assert.Equal(t, `'plain'`, posixSingleQuote("plain"))
	assert.Equal(t, `'with space'`, posixSingleQuote("with space"))
	assert.Equal(t, `'it'\''s'`, posixSingleQuote("it's"))
	assert.Equal(t, `''`, posixSingleQuote(""))
}

func TestPowershellSingleQuote(t *testing.T) {
	assert.Equal(t, `'plain'`, powershellSingleQuote("plain"))
	assert.Equal(t, `'with space'`, powershellSingleQuote("with space"))
	assert.Equal(t, `'it''s'`, powershellSingleQuote("it's"))
	assert.Equal(t, `''`, powershellSingleQuote(""))
}

func TestIsValidEnvName(t *testing.T) {
	for _, name := range []string{"A", "_A1", "JOB_RECORD_ID", "lower_case", "A1_B2"} {
		assert.True(t, isValidEnvName(name), "expected %q to be valid", name)
	}
	for _, name := range []string{"", "1A", "A-B", "A B", "A.B", "中文"} {
		assert.False(t, isValidEnvName(name), "expected %q to be invalid", name)
	}
}

func TestBuildRemoteEnvVars(t *testing.T) {
	uc := newRemoteExecFixture()
	ctx := context.Background()

	t.Run("merges and filters", func(t *testing.T) {
		record := &ScriptRecord{
			ID:      7,
			EnvVars: `{"B":"2","A":"1","BAD-NAME":"x","9BAD":"y"}`,
		}
		got := uc.buildRemoteEnvVars(ctx, record)
		assert.Equal(t, []remoteEnvVar{
			{name: "JOB_RECORD_ID", value: "7"},
			{name: "A", value: "1"},
			{name: "B", value: "2"},
		}, got)
	})

	t.Run("invalid json", func(t *testing.T) {
		got := uc.buildRemoteEnvVars(ctx, &ScriptRecord{ID: 8, EnvVars: "not-json"})
		assert.Equal(t, []remoteEnvVar{{name: "JOB_RECORD_ID", value: "8"}}, got)
	})

	t.Run("empty json", func(t *testing.T) {
		got := uc.buildRemoteEnvVars(ctx, &ScriptRecord{ID: 9})
		assert.Equal(t, []remoteEnvVar{{name: "JOB_RECORD_ID", value: "9"}}, got)
	})
}

func TestBuildSSHRemoteCommand(t *testing.T) {
	uc := newRemoteExecFixture()

	record := &ScriptRecord{
		WorkDir:    "/opt/app data",
		ScriptArgs: "hello world",
	}
	command := uc.buildSSHRemoteCommand(record, "/tmp/script dir/run.sh", []remoteEnvVar{
		{name: "JOB_RECORD_ID", value: "7"},
		{name: "GREETING", value: "hi there"},
	})

	assert.Equal(t,
		`mkdir -p '/opt/app data' && cd '/opt/app data'`+
			` && export JOB_RECORD_ID='7'`+
			` && export GREETING='hi there'`+
			` && '/tmp/script dir/run.sh' 'hello' 'world'`,
		command,
	)
}

func TestBuildSSHRemoteCommand_NoWorkDir(t *testing.T) {
	uc := newRemoteExecFixture()

	command := uc.buildSSHRemoteCommand(&ScriptRecord{}, "/tmp/run.sh", nil)
	assert.Equal(t, `'/tmp/run.sh'`, command)
}

func TestBuildWinRMRemoteCommand(t *testing.T) {
	uc := newRemoteExecFixture()

	record := &ScriptRecord{
		WorkDir:    `C:\work dir`,
		ScriptArgs: "hello world",
	}
	command := uc.buildWinRMRemoteCommand(record, "grain_1_abc.ps1", []remoteEnvVar{
		{name: "JOB_RECORD_ID", value: "7"},
	})

	assert.Equal(t,
		`$ErrorActionPreference = 'Continue'`+
			`; $p = Join-Path $env:TEMP 'grain_1_abc.ps1'`+
			`; New-Item -ItemType Directory -Force -Path 'C:\work dir' | Out-Null`+
			`; Set-Location -LiteralPath 'C:\work dir'`+
			`; $env:JOB_RECORD_ID = '7'`+
			`; & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $p 'hello' 'world'`+
			`; $code = $LASTEXITCODE`+
			`; Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue`+
			`; exit $code`,
		command,
	)
}

func TestWinRMConnectionTarget(t *testing.T) {
	tests := []struct {
		name     string
		hostVars common.AnsibleHostVars
		wantPort int
		wantTLS  bool
	}{
		{name: "defaults to http", hostVars: common.AnsibleHostVars{}, wantPort: 5985, wantTLS: false},
		{name: "https scheme", hostVars: common.AnsibleHostVars{AnsibleWinRMScheme: "https"}, wantPort: 5986, wantTLS: true},
		{name: "http scheme", hostVars: common.AnsibleHostVars{AnsibleWinRMScheme: "http"}, wantPort: 5985, wantTLS: false},
		{name: "https port infers tls", hostVars: common.AnsibleHostVars{AnsiblePort: 5986}, wantPort: 5986, wantTLS: true},
		{name: "custom port", hostVars: common.AnsibleHostVars{AnsiblePort: 1234}, wantPort: 1234, wantTLS: false},
		{name: "custom port with https", hostVars: common.AnsibleHostVars{AnsiblePort: 1234, AnsibleWinRMScheme: "https"}, wantPort: 1234, wantTLS: true},
		{name: "invalid port", hostVars: common.AnsibleHostVars{AnsiblePort: 0, AnsibleWinRMScheme: "https"}, wantPort: 5986, wantTLS: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port, useTLS := winRMConnectionTarget(&tt.hostVars)
			assert.Equal(t, tt.wantPort, port)
			assert.Equal(t, tt.wantTLS, useTLS)
		})
	}
}

func TestIsWinRMCertValidationIgnored(t *testing.T) {
	for _, value := range []string{"ignore", "IGNORE", "false", "0", "no", "disabled"} {
		assert.True(t, isWinRMCertValidationIgnored(value), "expected %q to skip validation", value)
	}
	for _, value := range []string{"", "validate", "true", "yes", "unknown"} {
		assert.False(t, isWinRMCertValidationIgnored(value), "expected %q to validate certificates", value)
	}
}

func TestRemoteExecutionID(t *testing.T) {
	ctx := context.WithValue(context.Background(), scriptRecordUUIDKey, "fixed-id")
	assert.Equal(t, "fixed-id", remoteExecutionID(ctx))

	generated := remoteExecutionID(context.Background())
	require.NotEmpty(t, generated)
	assert.NotEqual(t, "fixed-id", generated)
}
