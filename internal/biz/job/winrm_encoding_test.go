package job

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/encoding/unicode"
)

const encodedCommandPrefix = "powershell.exe -EncodedCommand "

func decodeWinRMCommand(t *testing.T, encoded string) string {
	t.Helper()
	require.True(t, strings.HasPrefix(encoded, encodedCommandPrefix),
		"the WinRM cmd shell must only see powershell.exe -EncodedCommand, got %q", encoded)

	payload := strings.TrimPrefix(encoded, encodedCommandPrefix)
	raw, err := base64.StdEncoding.DecodeString(payload)
	require.NoError(t, err)

	decoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
	script, err := decoder.String(string(raw))
	require.NoError(t, err)
	return script
}

func TestEncodeWinRMPowerShellHidesMetacharacters(t *testing.T) {
	script := "$x = 'a&calc|b<c>d'; Write-Output $x"

	encoded, err := encodeWinRMPowerShell(script)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(encoded, encodedCommandPrefix))

	// cmd.exe never sees the script: the payload is base64, which cannot carry
	// cmd metacharacters or PowerShell quotes.
	for _, token := range []string{"&", "|", "<", ">", ";", "'"} {
		assert.NotContains(t, encoded, token)
	}
	assert.Contains(t, decodeWinRMCommand(t, encoded), script)
}

func TestBuildWinRMRemoteCommandInjectionStaysInsideEncodedScript(t *testing.T) {
	uc := &ScriptRecordUseCache{}
	record := &ScriptRecord{
		WorkDir:    `C:\x&calc&rem`,
		ScriptArgs: "a&calc b",
	}
	script := uc.buildWinRMRemoteCommand(record, "grain.ps1", []remoteEnvVar{
		{name: "MODE", value: "x&calc"},
	})

	// Values stay single-quoted inside the PowerShell script, as designed.
	assert.Contains(t, script, `'C:\x&calc&rem'`)
	assert.Contains(t, script, `'x&calc'`)
	assert.Contains(t, script, `'a&calc'`)

	encoded, err := encodeWinRMPowerShell(script)
	require.NoError(t, err)

	// The outer command handed to cmd.exe contains no metacharacters, so the
	// `&calc&rem` payload cannot break out of the argument context.
	for _, token := range []string{"&", "|", "<", ">", "^", "%"} {
		assert.NotContains(t, encoded, token)
	}
	assert.Contains(t, decodeWinRMCommand(t, encoded), `C:\x&calc&rem`)
}

func TestEncodeWinRMPowerShellPreservesScript(t *testing.T) {
	script := "Write-Output 'hello'; exit 0"

	encoded, err := encodeWinRMPowerShell(script)
	require.NoError(t, err)
	assert.Contains(t, decodeWinRMCommand(t, encoded), script)
}
