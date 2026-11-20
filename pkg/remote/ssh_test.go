package remote

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"grain/pkg/errorx"
)

func TestDialSSH_Validation(t *testing.T) {
	ctx := context.Background()
	authMethods := []ssh.AuthMethod{ssh.Password("secret")}

	tests := []struct {
		name string
		cfg  SSHConfig
	}{
		{name: "missing address", cfg: SSHConfig{User: "root", AuthMethods: authMethods}},
		{name: "missing user", cfg: SSHConfig{Addr: "127.0.0.1:22", AuthMethods: authMethods}},
		{name: "missing auth", cfg: SSHConfig{Addr: "127.0.0.1:22", User: "root"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := DialSSH(ctx, tt.cfg)
			require.Error(t, err)
			assert.Nil(t, client)
			assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))
		})
	}
}

func TestResolveSSHAuth_PrivateKey(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(privateKey, "")
	require.NoError(t, err)

	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600))

	methods, cleanup, err := ResolveSSHAuth(context.Background(), SSHAuthConfig{
		PrivateKeyPath: keyPath,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, methods)
	require.NotNil(t, cleanup)
	cleanup()
}

func TestResolveSSHAuth_Password(t *testing.T) {
	methods, cleanup, err := ResolveSSHAuth(context.Background(), SSHAuthConfig{
		Password: "secret",
	})
	require.NoError(t, err)
	// Password authentication plus the keyboard-interactive fallback.
	assert.Len(t, methods, 2)
	cleanup()
}

func TestResolveSSHAuth_NoCredentials(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")

	methods, _, err := ResolveSSHAuth(context.Background(), SSHAuthConfig{
		EnableAgent:       true,
		EnableDefaultKeys: false,
	})
	require.Error(t, err)
	assert.Nil(t, methods)
	assert.True(t, errorx.IsCode(err, errorx.CodeConfigError))
}

func TestResolveSSHAuth_MissingPrivateKey(t *testing.T) {
	methods, _, err := ResolveSSHAuth(context.Background(), SSHAuthConfig{
		PrivateKeyPath: "/nonexistent/id_ed25519",
	})
	require.Error(t, err)
	assert.Nil(t, methods)
	assert.True(t, errorx.IsCode(err, errorx.CodeConfigError))
}

func TestRunSSHCommand_NilClient(t *testing.T) {
	err := RunSSHCommand(context.Background(), nil, "whoami", nil, nil, nil)
	require.Error(t, err)
	assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))
}

func TestSSHConfig_NilHostKeyCallbackFailsClosed(t *testing.T) {
	cfg := SSHConfig{}.withDefaults()
	require.NotNil(t, cfg.HostKeyCallback)
	err := cfg.HostKeyCallback("example.com:22", nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "主机密钥")
}
