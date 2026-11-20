package remote

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"grain/pkg/errorx"
)

const agentDialTimeout = 5 * time.Second

// SSHConfig describes one SSH connection attempt.
type SSHConfig struct {
	// Addr is the host:port pair to dial.
	Addr string
	// User is the SSH login user.
	User string
	// AuthMethods are tried in order by the SSH handshake. At least one is
	// required; use ResolveSSHAuth to build them from common credential
	// sources.
	AuthMethods []ssh.AuthMethod
	// Timeout bounds the TCP dial and the SSH handshake. Zero means
	// DefaultSSHTimeout.
	Timeout time.Duration
	// HostKeyCallback verifies the server host key. Nil fails closed: callers
	// must either pin a known key (ssh.FixedHostKey) or explicitly opt into
	// trust-on-first-use with CaptureHostKey.
	HostKeyCallback ssh.HostKeyCallback
}

func (c SSHConfig) withDefaults() SSHConfig {
	if c.Timeout <= 0 {
		c.Timeout = DefaultSSHTimeout
	}
	if c.HostKeyCallback == nil {
		c.HostKeyCallback = func(hostname string, _ net.Addr, _ ssh.PublicKey) error {
			return errorx.CodeConfigError.Errorf("拒绝连接 %s：未配置 SSH 主机密钥校验", hostname)
		}
	}
	return c
}

// DialSSH opens the TCP connection and performs the SSH handshake, applying
// the configured timeout to both steps and honoring the context deadline.
func DialSSH(ctx context.Context, cfg SSHConfig) (*ssh.Client, error) {
	cfg = cfg.withDefaults()

	if strings.TrimSpace(cfg.Addr) == "" {
		return nil, errorx.CodeMissingParam.Error("SSH地址不能为空")
	}
	if strings.TrimSpace(cfg.User) == "" {
		return nil, errorx.CodeMissingParam.Error("SSH用户名不能为空")
	}
	if len(cfg.AuthMethods) == 0 {
		return nil, errorx.CodeMissingParam.Error("SSH认证方式不能为空")
	}

	dialer := &net.Dialer{Timeout: cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", cfg.Addr)
	if err != nil {
		return nil, errorx.Wrapf(err, errorx.CodeSSHConnectionFailed, "SSH连接失败: %s", cfg.Addr)
	}

	deadline := time.Now().Add(cfg.Timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)

	clientCfg := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            cfg.AuthMethods,
		HostKeyCallback: cfg.HostKeyCallback,
		Timeout:         cfg.Timeout,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, cfg.Addr, clientCfg)
	if err != nil {
		_ = conn.Close()
		return nil, errorx.Wrapf(err, errorx.CodeSSHConnectionFailed, "SSH握手失败: %s", cfg.Addr)
	}
	_ = conn.SetDeadline(time.Time{})

	return ssh.NewClient(sshConn, chans, reqs), nil
}

// RunSSHCommand runs one command in a new SSH session, streaming stdin/stdout/
// stderr through the supplied readers and writers.
//
// Cancellation closes the session and the client so a goroutine blocked in
// session.Run always unblocks; callers must not reuse the client afterwards.
func RunSSHCommand(
	ctx context.Context,
	client *ssh.Client,
	command string,
	stdin io.Reader,
	stdout, stderr io.Writer,
) error {
	if client == nil {
		return errorx.CodeInvalidParam.Error("SSH客户端不能为空")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("创建SSH会话失败: %w", err)
	}
	defer func() { _ = session.Close() }()

	if stdin != nil {
		session.Stdin = stdin
	}
	if stdout != nil {
		session.Stdout = stdout
	}
	if stderr != nil {
		session.Stderr = stderr
	}

	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()

	select {
	case runErr := <-done:
		return runErr
	case <-ctx.Done():
		_ = session.Close()
		_ = client.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		return ctx.Err()
	}
}

// RunSSHCommandCombined runs a command and returns its combined stdout/stderr.
// Unlike passing the same bytes.Buffer to RunSSHCommand for both streams, the
// internal writer serializes the two copy goroutines safely.
func RunSSHCommandCombined(ctx context.Context, client *ssh.Client, command string) ([]byte, error) {
	var combined combinedWriter
	err := RunSSHCommand(ctx, client, command, nil, &combined, &combined)
	return combined.Bytes(), err
}

type combinedWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *combinedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *combinedWriter) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf.Bytes()...)
}

// SSHAuthConfig describes the credential sources to try for an SSH connection.
// Explicit credentials are always tried first, followed by the agent and the
// default user keys when enabled.
type SSHAuthConfig struct {
	// Password enables password and keyboard-interactive authentication.
	Password string
	// PrivateKeyPath enables public key authentication with the given key.
	PrivateKeyPath string
	// PrivateKeyPassphrase decrypts an encrypted private key.
	PrivateKeyPassphrase string
	// EnableAgent enables SSH agent authentication using SSH_AUTH_SOCK.
	EnableAgent bool
	// EnableDefaultKeys enables fallback keys under ~/.ssh.
	EnableDefaultKeys bool
}

// ResolveSSHAuth builds SSH authentication methods from common credential
// sources. The returned cleanup closes any SSH agent connection and must be
// called once the connection is no longer needed.
func ResolveSSHAuth(
	ctx context.Context,
	cfg SSHAuthConfig,
) ([]ssh.AuthMethod, func(), error) {
	var methods []ssh.AuthMethod
	var closers []func()
	cleanup := func() {
		for _, closeFn := range closers {
			closeFn()
		}
	}

	if password := cfg.Password; password != "" {
		methods = append(methods, ssh.Password(password))
		// Some servers disable plain password auth and only offer
		// keyboard-interactive; answer every prompt with the same secret.
		methods = append(methods, ssh.KeyboardInteractive(
			func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = password
				}
				return answers, nil
			},
		))
	}

	if keyPath := strings.TrimSpace(cfg.PrivateKeyPath); keyPath != "" {
		signer, err := loadPrivateKey(keyPath, cfg.PrivateKeyPassphrase)
		if err != nil {
			cleanup()
			return nil, func() {}, errorx.Wrapf(err, errorx.CodeConfigError,
				"加载SSH私钥失败: %s", keyPath)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	var agentErr error
	if cfg.EnableAgent {
		if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
			dialer := &net.Dialer{Timeout: agentDialTimeout}
			conn, err := dialer.DialContext(ctx, "unix", sock)
			if err != nil {
				agentErr = err
			} else {
				methods = append(methods, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
				closers = append(closers, func() { _ = conn.Close() })
			}
		}
	}

	if cfg.EnableDefaultKeys {
		for _, keyPath := range defaultKeyPaths() {
			signer, err := loadPrivateKey(keyPath, "")
			if err != nil {
				// Missing or unreadable fallback keys are expected.
				continue
			}
			methods = append(methods, ssh.PublicKeys(signer))
		}
	}

	if len(methods) == 0 {
		cleanup()
		if agentErr != nil {
			return nil, func() {}, errorx.Wrapf(agentErr, errorx.CodeConfigError,
				"未找到可用的SSH认证方式，SSH agent连接失败")
		}
		return nil, func() {}, errorx.CodeConfigError.Error(
			"未找到可用的SSH认证方式，请配置密码、私钥或 SSH agent")
	}
	return methods, cleanup, nil
}

func loadPrivateKey(keyPath, passphrase string) (ssh.Signer, error) {
	// #nosec G304 -- path is provided by the caller's host configuration
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	if passphrase != "" {
		signer, err := ssh.ParsePrivateKeyWithPassphrase(data, []byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("解析带口令的SSH私钥失败: %w", err)
		}
		return signer, nil
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("解析SSH私钥失败（如私钥带口令，请配置 passphrase）: %w", err)
	}
	return signer, nil
}

func defaultKeyPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}
	names := []string{"id_ed25519", "id_ecdsa", "id_rsa"}
	paths := make([]string, 0, len(names))
	for _, name := range names {
		paths = append(paths, filepath.Join(home, ".ssh", name))
	}
	return paths
}

// MarshalHostKey renders a server host key as an authorized_keys line, which is
// the representation persisted with a managed host.
func MarshalHostKey(key ssh.PublicKey) string {
	if key == nil {
		return ""
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

// ParseHostKey parses an authorized_keys line produced by MarshalHostKey.
func ParseHostKey(value string) (ssh.PublicKey, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errorx.CodeMissingParam.Error("SSH主机密钥不能为空")
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(value))
	if err != nil {
		return nil, fmt.Errorf("解析SSH主机密钥失败: %w", err)
	}
	return key, nil
}

// HostKeyFingerprint returns the SHA256 fingerprint used for display and audit.
func HostKeyFingerprint(key ssh.PublicKey) string {
	if key == nil {
		return ""
	}
	return ssh.FingerprintSHA256(key)
}

// CaptureHostKey returns a callback that records the server host key and
// accepts it. It must only be used during first-time onboarding (trust on first
// use); later connections must verify against the captured key.
func CaptureHostKey(dst *ssh.PublicKey) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if dst != nil {
			*dst = key
		}
		return nil
	}
}
