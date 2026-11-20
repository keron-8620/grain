package job

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"grain/internal/biz/common"
)

// startTestSSHServer starts an in-process SSH server that executes received
// "exec" requests with /bin/sh. It lets the remote execution path be exercised
// without an external SSH daemon.
func startTestSSHServer(t *testing.T) (port uint16, hostKey string) {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(privateKey)
	require.NoError(t, err)

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serveTestSSHConn(conn, config)
		}
	}()

	addr, ok := listener.Addr().(*net.TCPAddr)
	require.True(t, ok)
	return uint16(addr.Port), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}

func serveTestSSHConn(conn net.Conn, config *ssh.ServerConfig) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer func() { _ = sshConn.Close() }()
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}

		go func() {
			defer func() { _ = channel.Close() }()

			for req := range requests {
				if req.Type != "exec" {
					_ = req.Reply(false, nil)
					continue
				}

				var payload struct {
					Command string
				}
				if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
					_ = req.Reply(false, nil)
					return
				}
				_ = req.Reply(true, nil)

				// #nosec G204 -- test-only server executing its own commands
				cmd := exec.Command("/bin/sh", "-c", payload.Command)
				cmd.Stdin = channel
				cmd.Stdout = channel
				cmd.Stderr = channel

				status := 0
				if err := cmd.Run(); err != nil {
					var exitErr *exec.ExitError
					if errors.As(err, &exitErr) {
						status = exitErr.ExitCode()
					} else {
						status = 1
					}
				}

				_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct {
					Status uint32
				}{uint32(status)}))
				return
			}
		}()
	}
}

func writeTestClientKey(t *testing.T) string {
	t.Helper()

	_, clientKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(clientKey, "")
	require.NoError(t, err)

	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600))
	return keyPath
}

func TestExecuteSSH_RemoteExecution(t *testing.T) {
	port, hostKey := startTestSSHServer(t)
	keyPath := writeTestClientKey(t)

	scriptPath := filepath.Join(t.TempDir(), "remote.sh")
	require.NoError(t, os.WriteFile(scriptPath,
		[]byte("#!/bin/sh\necho \"ARGS=$1 $2\"\necho \"GREETING=$GREETING\"\nexit 7\n"), 0o700))

	logPath := filepath.Join(t.TempDir(), "exec.log")
	logFile, err := os.Create(logPath)
	require.NoError(t, err)
	defer func() { _ = logFile.Close() }()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	uc := NewScriptRecordUseCache(nil, newMockScriptRecordRepo(), logger, 1)
	record := &ScriptRecord{
		ID:         42,
		Status:     ScriptRecordStatusPending,
		ExitCode:   -1,
		ScriptArgs: "hello world",
		EnvVars:    `{"GREETING":"hi there"}`,
		Timeout:    10,
		HostID:     1,
	}

	executionID := fmt.Sprintf("test-%d", time.Now().UnixNano())
	ctx, cancel := context.WithTimeout(
		context.WithValue(context.Background(), scriptRecordUUIDKey, executionID),
		10*time.Second,
	)
	defer cancel()

	hostVars := &common.AnsibleHostVars{
		AnsibleHost:              "127.0.0.1",
		AnsiblePort:              port,
		AnsibleUser:              "tester",
		AnsibleConnection:        common.ProtocolSSH,
		AnsibleSSHPrivateKeyFile: keyPath,
		AnsibleSSHHostKey:        hostKey,
	}

	runErr := uc.executeSSH(ctx, record, scriptPath, logPath, logFile, hostVars)
	require.Error(t, runErr)
	assert.Equal(t, 7, record.ExitCode)
	assert.Equal(t, ScriptRecordStatusRunning, record.Status)

	logBytes, err := os.ReadFile(logPath)
	require.NoError(t, err)
	logStr := string(logBytes)
	assert.Contains(t, logStr, "ARGS=hello world")
	assert.Contains(t, logStr, "GREETING=hi there")
	assert.Contains(t, logStr, "开始远程执行 (SSH:")

	// The per-execution remote directory must be removed on exit.
	_, statErr := os.Stat(filepath.Join("/tmp", "grain-exec-"+executionID))
	assert.True(t, os.IsNotExist(statErr), "remote script directory should be cleaned up")
}

func TestExecuteSSH_RejectsHostKeyMismatch(t *testing.T) {
	port, _ := startTestSSHServer(t)
	keyPath := writeTestClientKey(t)

	// Pin a different (attacker-controlled) key: the handshake must be refused.
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	otherSigner, err := ssh.NewSignerFromKey(otherKey)
	require.NoError(t, err)
	wrongKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(otherSigner.PublicKey())))

	scriptPath := filepath.Join(t.TempDir(), "remote.sh")
	require.NoError(t, os.WriteFile(scriptPath, []byte("#!/bin/sh\necho should-not-run\n"), 0o700))

	logPath := filepath.Join(t.TempDir(), "exec.log")
	logFile, err := os.Create(logPath)
	require.NoError(t, err)
	defer func() { _ = logFile.Close() }()

	uc := NewScriptRecordUseCache(nil, newMockScriptRecordRepo(), slog.New(slog.NewTextHandler(io.Discard, nil)), 1)
	record := &ScriptRecord{
		ID:       43,
		Status:   ScriptRecordStatusPending,
		ExitCode: -1,
		Timeout:  10,
		HostID:   1,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	runErr := uc.executeSSH(ctx, record, scriptPath, logPath, logFile, &common.AnsibleHostVars{
		AnsibleHost:              "127.0.0.1",
		AnsiblePort:              port,
		AnsibleUser:              "tester",
		AnsibleConnection:        common.ProtocolSSH,
		AnsibleSSHPrivateKeyFile: keyPath,
		AnsibleSSHHostKey:        wrongKey,
	})
	require.Error(t, runErr)
	assert.Contains(t, runErr.Error(), "主机密钥")
	assert.Equal(t, ScriptRecordStatusFailed, record.Status)

	logBytes, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.Contains(t, string(logBytes), "主机密钥")
}

func TestExecuteSSH_RejectsPasswordAuth(t *testing.T) {
	port, hostKey := startTestSSHServer(t)
	keyPath := writeTestClientKey(t)

	scriptPath := filepath.Join(t.TempDir(), "remote.sh")
	require.NoError(t, os.WriteFile(scriptPath, []byte("#!/bin/sh\nexit 0\n"), 0o700))
	logPath := filepath.Join(t.TempDir(), "exec.log")
	logFile, err := os.Create(logPath)
	require.NoError(t, err)
	defer func() { _ = logFile.Close() }()

	uc := NewScriptRecordUseCache(nil, newMockScriptRecordRepo(), slog.New(slog.NewTextHandler(io.Discard, nil)), 1)
	record := &ScriptRecord{ID: 44, Status: ScriptRecordStatusPending, ExitCode: -1, Timeout: 5, HostID: 1}

	runErr := uc.executeSSH(context.Background(), record, scriptPath, logPath, logFile, &common.AnsibleHostVars{
		AnsibleHost:              "127.0.0.1",
		AnsiblePort:              port,
		AnsibleUser:              "tester",
		AnsibleConnection:        common.ProtocolSSH,
		AnsibleSSHPrivateKeyFile: keyPath,
		AnsibleSSHHostKey:        hostKey,
		AnsiblePassword:          "should-not-be-used",
	})
	require.Error(t, runErr)
	assert.Contains(t, runErr.Error(), "密码")
	assert.Equal(t, ScriptRecordStatusFailed, record.Status)
}
