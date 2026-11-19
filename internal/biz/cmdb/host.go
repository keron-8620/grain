package cmdb

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/masterzen/winrm"
	"golang.org/x/crypto/ssh"

	"grain/pkg/db"
	"grain/pkg/errorx"
)

const (
	protocolSSH   = "ssh"
	protocolWinRM = "winrm"

	osTypeLinux   = "linux"
	osTypeWindows = "windows"

	defaultSSHTimeout     = 15 * time.Second
	defaultSSHPort        = 22
	defaultWinRMPort      = 5985
	defaultWinRMHTTPSPort = 5986
)

// Host is the host domain model (Domain Object - DO).
type Host struct {
	ID        uint64
	Name      string
	Label     string
	HostIP    string
	HostPort  uint16
	HostUser  string
	Protocol  string
	PyPath    string
	Remark    string
	OSType    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// HostRepo is the Host repository interface contract.
type HostRepo interface {
	Create(ctx context.Context, host *Host) (*Host, error)
	Update(ctx context.Context, host *Host) (*Host, error)
	Delete(ctx context.Context, id uint64) error
	FindByID(ctx context.Context, id uint64) (*Host, error)
	FindByIDs(ctx context.Context, ids []uint64) ([]Host, error)
	List(ctx context.Context, opts db.ListOptions) ([]Host, int64, error)
	ExistsByHostIPPortUser(ctx context.Context, ip string, port uint16, user string, filters []db.ListFilter) (bool, error)
}

// WinRMConfig holds TLS and mutual-auth certificate settings for WinRM onboarding.
type WinRMConfig struct {
	UseTLS         bool
	Insecure       bool
	CACert         []byte
	ClientCertPath string
	ClientKeyPath  string
}

// HostUseCaseOption configures optional dependencies or protocol settings on HostUseCase.
type HostUseCaseOption func(*HostUseCase)

// WithWinRMConfig sets the WinRM connection and client certificate configuration.
func WithWinRMConfig(cfg WinRMConfig) HostUseCaseOption {
	return func(uc *HostUseCase) {
		uc.winrmUseTLS = cfg.UseTLS
		uc.winrmInsecure = cfg.Insecure
		uc.winrmCACert = cfg.CACert
		uc.winrmClientCertPath = strings.TrimSpace(cfg.ClientCertPath)
		uc.winrmClientKeyPath = strings.TrimSpace(cfg.ClientKeyPath)
		// x509 client certificate auth requires HTTPS/TLS.
		if (uc.winrmClientCertPath != "" || uc.winrmClientKeyPath != "") && !uc.winrmUseTLS {
			uc.winrmUseTLS = true
		}
	}
}

// HostUseCase manages the host inventory and onboards new hosts by deploying
// the configured public keys or verifying connectivity so that later operations
// can run passwordless.
type HostUseCase struct {
	repo       HostRepo
	logger     *slog.Logger
	sshTimeout time.Duration
	authMethod ssh.AuthMethod
	pubKeyB64s []string

	winrmUseTLS         bool
	winrmInsecure       bool
	winrmCACert         []byte
	winrmClientCertPath string
	winrmClientKeyPath  string
}

func NewHostUseCase(
	repo HostRepo,
	logger *slog.Logger,
	sshTimeout time.Duration,
	authMethod ssh.AuthMethod,
	pubKeyB64s []string,
	opts ...HostUseCaseOption,
) *HostUseCase {
	if logger == nil {
		logger = slog.Default()
	}
	if sshTimeout <= 0 {
		sshTimeout = defaultSSHTimeout
	}
	uc := &HostUseCase{
		repo:       repo,
		logger:     logger,
		sshTimeout: sshTimeout,
		authMethod: authMethod,
		pubKeyB64s: pubKeyB64s,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(uc)
		}
	}
	return uc
}

// Create validates and persists a new host. For SSH hosts it first deploys the
// configured public keys to the target user's authorized_keys so that the host
// is immediately reachable without a password. For WinRM hosts it verifies
// certificate-based connectivity when configured. If onboarding fails the host
// is not persisted, so a retry starts from a clean state.
func (uc *HostUseCase) Create(ctx context.Context, host *Host) (*Host, error) {
	if host == nil {
		return nil, errorx.CodeInvalidParam.Error("主机信息不能为空")
	}
	if err := uc.applyDefaults(host); err != nil {
		return nil, err
	}

	exists, err := uc.repo.ExistsByHostIPPortUser(ctx, host.HostIP, host.HostPort, host.HostUser, nil)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if exists {
		return nil, errorx.CodeDuplicatedKey.Error("该主机连接信息已存在")
	}

	if err := uc.deployPasswordlessKey(ctx, host); err != nil {
		return nil, err
	}

	created, err := uc.repo.Create(ctx, host)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	return created, nil
}

// Update replaces an existing host record. Callers must provide a complete
// entity; connection defaults and the duplicate check are applied again.
// When the connection settings (IP, port, user, protocol, OS type) change, the
// passwordless key is redeployed (or WinRM re-verified) before saving.
func (uc *HostUseCase) Update(ctx context.Context, host *Host) (*Host, error) {
	if host == nil || host.ID == 0 {
		return nil, errorx.CodeInvalidParam.Error("无效的主机ID")
	}
	if err := uc.applyDefaults(host); err != nil {
		return nil, err
	}

	oldHost, err := uc.repo.FindByID(ctx, host.ID)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if oldHost == nil {
		return nil, errorx.CodeRecordNotFound.Error("主机不存在")
	}

	exists, err := uc.repo.ExistsByHostIPPortUser(ctx, host.HostIP, host.HostPort, host.HostUser, []db.ListFilter{
		{Field: "id", Op: db.ListFilterNotEquals, Value: host.ID},
	})
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if exists {
		return nil, errorx.CodeDuplicatedKey.Error("该主机连接信息已存在")
	}

	if connectionSettingsChanged(oldHost, host) {
		if err := uc.deployPasswordlessKey(ctx, host); err != nil {
			return nil, err
		}
	}

	updated, err := uc.repo.Update(ctx, host)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	return updated, nil
}

// connectionSettingsChanged reports whether the update targets a different
// connection endpoint or protocol, which requires onboarding to run again.
func connectionSettingsChanged(oldHost, newHost *Host) bool {
	return oldHost.HostIP != newHost.HostIP ||
		oldHost.HostPort != newHost.HostPort ||
		oldHost.HostUser != newHost.HostUser ||
		oldHost.Protocol != newHost.Protocol ||
		oldHost.OSType != newHost.OSType
}

// Delete removes a host by ID.
func (uc *HostUseCase) Delete(ctx context.Context, id uint64) error {
	if id == 0 {
		return errorx.CodeInvalidParam.Error("无效的主机ID")
	}

	host, err := uc.repo.FindByID(ctx, id)
	if err != nil {
		return errorx.FromDBError(err)
	}
	if host == nil {
		return errorx.CodeRecordNotFound.Error("主机不存在")
	}

	if err := uc.repo.Delete(ctx, id); err != nil {
		return errorx.FromDBError(err)
	}
	return nil
}

// Get returns a host by ID.
func (uc *HostUseCase) Get(ctx context.Context, id uint64) (*Host, error) {
	if id == 0 {
		return nil, errorx.CodeInvalidParam.Error("无效的主机ID")
	}

	host, err := uc.repo.FindByID(ctx, id)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if host == nil {
		return nil, errorx.CodeRecordNotFound.Error("主机不存在")
	}
	return host, nil
}

// GetByIDs returns hosts for the given IDs.
func (uc *HostUseCase) GetByIDs(ctx context.Context, ids []uint64) ([]Host, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	hosts, err := uc.repo.FindByIDs(ctx, ids)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	return hosts, nil
}

// List lists hosts with pagination, filters, and ordering.
func (uc *HostUseCase) List(ctx context.Context, opts db.ListOptions) ([]Host, int64, error) {
	hosts, total, err := uc.repo.List(ctx, opts)
	if err != nil {
		return nil, 0, errorx.FromDBError(err)
	}
	return hosts, total, nil
}

// applyDefaults normalizes user input and fills protocol-specific defaults.
func (uc *HostUseCase) applyDefaults(host *Host) error {
	host.Name = strings.TrimSpace(host.Name)
	host.HostIP = strings.TrimSpace(host.HostIP)
	host.HostUser = strings.TrimSpace(host.HostUser)
	host.Protocol = strings.ToLower(strings.TrimSpace(host.Protocol))
	host.OSType = strings.ToLower(strings.TrimSpace(host.OSType))

	if host.Name == "" {
		return errorx.CodeMissingParam.Error("主机名称不能为空")
	}
	if host.HostIP == "" {
		return errorx.CodeMissingParam.Error("主机IP不能为空")
	}
	if host.HostUser == "" {
		return errorx.CodeMissingParam.Error("主机用户名不能为空")
	}

	if host.Protocol == "" {
		host.Protocol = protocolSSH
	}
	switch host.Protocol {
	case protocolSSH:
		if host.HostPort == 0 {
			host.HostPort = defaultSSHPort
		}
	case protocolWinRM:
		if host.HostPort == 0 {
			if uc.winrmUseTLS {
				host.HostPort = defaultWinRMHTTPSPort
			} else {
				host.HostPort = defaultWinRMPort
			}
		}
		if host.OSType == "" {
			host.OSType = osTypeWindows
		}
	default:
		return errorx.CodeProtocolUnsupported.Error("不支持的连接协议: " + host.Protocol)
	}

	if host.OSType == "" {
		host.OSType = osTypeLinux
	}
	return nil
}

// deployPasswordlessKey dispatches protocol-specific passwordless onboarding.
func (uc *HostUseCase) deployPasswordlessKey(ctx context.Context, host *Host) error {
	switch host.Protocol {
	case protocolSSH:
		return uc.deploySSHKey(ctx, host)
	case protocolWinRM:
		return uc.verifyWinRMConnection(ctx, host)
	default:
		return errorx.CodeProtocolUnsupported.Error("不支持的连接协议: " + host.Protocol)
	}
}

func (uc *HostUseCase) deploySSHKey(ctx context.Context, host *Host) error {
	if host.OSType == osTypeWindows {
		return errorx.CodeInvalidParam.Errorf("windows机器不支持%s, 请使用%s", protocolSSH, protocolWinRM)
	}

	if len(uc.pubKeyB64s) == 0 {
		uc.logger.WarnContext(ctx, "no SSH public keys configured, skipping passwordless key deployment",
			slog.String("host_ip", host.HostIP), slog.Uint64("host_port", uint64(host.HostPort)))
		return nil
	}

	if uc.authMethod == nil {
		return errorx.CodeConfigError.Error("未配置 SSH 认证方式，无法部署免密公钥")
	}

	keys, err := normalizeAuthorizedKeys(uc.pubKeyB64s)
	if err != nil {
		return errorx.Wrap(err, errorx.CodeConfigError, "SSH免密公钥配置无效")
	}

	addr := net.JoinHostPort(host.HostIP, strconv.Itoa(int(host.HostPort)))
	client, err := uc.dialSSH(ctx, addr, host.HostUser)
	if err != nil {
		return err
	}

	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			uc.logger.WarnContext(ctx, "failed to close SSH client", slog.String("addr", addr), slog.Any("error", closeErr))
		}
	}()

	session, err := client.NewSession()
	if err != nil {
		return errorx.Wrap(err, errorx.CodeSSHKeyDeployFailed, fmt.Sprintf("创建SSH会话失败: %s", addr))
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil {
			uc.logger.DebugContext(ctx, "failed to close SSH session", slog.String("addr", addr), slog.Any("error", closeErr))
		}
	}()

	output, err := uc.runCommand(ctx, session, authorizedKeysScript(keys))
	if err != nil {
		msg := fmt.Sprintf("部署免密公钥失败: %s", addr)
		if detail := strings.TrimSpace(string(output)); detail != "" {
			msg += ": " + truncate(detail, 512)
		}
		return errorx.Wrap(err, errorx.CodeSSHKeyDeployFailed, msg)
	}

	uc.logger.InfoContext(ctx, "passwordless key deployed",
		slog.String("host_ip", host.HostIP),
		slog.Uint64("host_port", uint64(host.HostPort)),
		slog.String("host_user", host.HostUser),
		slog.Int("key_count", len(keys)),
	)
	return nil
}

func (uc *HostUseCase) dialSSH(ctx context.Context, addr, user string) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{uc.authMethod},
		// Host keys are not provisioned for managed hosts yet. This is the same
		// trust model as a first-time ssh(1) connection, but without TOFU.

		// #nosec G106 -- internal trusted network, skip host key check for automation
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         uc.sshTimeout,
	}

	dialer := &net.Dialer{Timeout: uc.sshTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, errorx.Wrap(err, errorx.CodeSSHConnectionFailed, fmt.Sprintf("SSH连接失败: %s", addr))
	}

	// ClientConfig.Timeout only covers the TCP dial; bound the handshake too.
	_ = conn.SetDeadline(time.Now().Add(uc.sshTimeout))
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, errorx.Wrap(err, errorx.CodeSSHConnectionFailed, fmt.Sprintf("SSH握手失败: %s", addr))
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(sshConn, chans, reqs), nil
}

// runCommand runs the onboarding script and bounds both command execution and
// context cancellation by closing the session.
func (uc *HostUseCase) runCommand(ctx context.Context, session *ssh.Session, cmd string) ([]byte, error) {
	type result struct {
		output []byte
		err    error
	}
	done := make(chan result, 1)
	go func() {
		output, err := session.CombinedOutput(cmd)
		done <- result{output: output, err: err}
	}()

	timer := time.NewTimer(uc.sshTimeout)
	defer timer.Stop()

	select {
	case res := <-done:
		return res.output, res.err
	case <-timer.C:
		_ = session.Close()
		return nil, context.DeadlineExceeded
	case <-ctx.Done():
		_ = session.Close()
		return nil, ctx.Err()
	}
}

func (uc *HostUseCase) verifyWinRMConnection(ctx context.Context, host *Host) error {
	if uc.winrmClientCertPath == "" && uc.winrmClientKeyPath == "" {
		uc.logger.WarnContext(ctx, "no WinRM client certificate configured, skipping connection verification",
			slog.String("host_ip", host.HostIP), slog.Uint64("host_port", uint64(host.HostPort)))
		return nil
	}
	if uc.winrmClientCertPath == "" || uc.winrmClientKeyPath == "" {
		return errorx.CodeConfigError.Error("WinRM 客户端证书与私钥路径必须同时配置")
	}

	clientCert, err := os.ReadFile(uc.winrmClientCertPath)
	if err != nil {
		return errorx.Wrap(err, errorx.CodeConfigError, "读取 WinRM 客户端证书失败")
	}
	clientKey, err := os.ReadFile(uc.winrmClientKeyPath)
	if err != nil {
		return errorx.Wrap(err, errorx.CodeConfigError, "读取 WinRM 客户端私钥失败")
	}

	endpoint := winrm.NewEndpoint(
		host.HostIP,
		int(host.HostPort),
		uc.winrmUseTLS,
		uc.winrmInsecure,
		uc.winrmCACert,
		clientCert,
		clientKey,
		uc.sshTimeout,
	)

	params := winrm.DefaultParameters
	params.TransportDecorator = func() winrm.Transporter {
		return &winrm.ClientAuthRequest{}
	}

	client, err := winrm.NewClientWithParameters(
		endpoint,
		host.HostUser,
		"",
		params,
	)
	if err != nil {
		return errorx.Wrap(err, errorx.CodeWinRMConnectionFailed, "创建 WinRM 客户端失败")
	}

	_, err = client.RunWithContext(ctx, "whoami", io.Discard, io.Discard)
	if err != nil {
		return errorx.Wrap(err, errorx.CodeWinRMConnectionFailed,
			fmt.Sprintf("WinRM 连接失败: %s:%d", host.HostIP, host.HostPort))
	}

	uc.logger.InfoContext(ctx, "WinRM connection verified",
		slog.String("host_ip", host.HostIP),
		slog.Uint64("host_port", uint64(host.HostPort)),
	)
	return nil
}

// authorizedKeysScript builds an idempotent POSIX shell snippet that ensures
// ~/.ssh and authorized_keys have safe permissions and appends missing keys.
func authorizedKeysScript(keys []string) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString("umask 077\n")
	b.WriteString("mkdir -p \"$HOME/.ssh\"\n")
	b.WriteString("touch \"$HOME/.ssh/authorized_keys\"\n")
	b.WriteString("chmod 700 \"$HOME/.ssh\"\n")
	b.WriteString("chmod 600 \"$HOME/.ssh/authorized_keys\"\n")
	for _, key := range keys {
		quoted := shellQuote(key)
		fmt.Fprintf(&b, "grep -qxF %s \"$HOME/.ssh/authorized_keys\" || printf '%%s\\n' %s >> \"$HOME/.ssh/authorized_keys\"\n", quoted, quoted)
	}
	return b.String()
}

// normalizeAuthorizedKeys accepts either base64-encoded wire-format public key
// blobs (ssh-rsa/ssh-ed25519 payload only) or full authorized_keys lines, and
// canonicalizes them to "type base64" lines without comments.
func normalizeAuthorizedKeys(raws []string) ([]string, error) {
	keys := make([]string, 0, len(raws))
	seen := make(map[string]struct{}, len(raws))

	for i, raw := range raws {
		key, err := normalizeAuthorizedKey(raw)
		if err != nil {
			return nil, fmt.Errorf("public key #%d: %w", i+1, err)
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no usable public keys")
	}
	return keys, nil
}

func normalizeAuthorizedKey(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("empty key")
	}

	// Full authorized_keys line, e.g. "ssh-ed25519 AAAA... user@host".
	if strings.ContainsAny(s, " \t") {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
		if err != nil {
			return "", fmt.Errorf("parse authorized_keys line: %w", err)
		}
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), nil
	}

	// Bare base64 payload of the wire-format public key.
	blob, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("decode base64 key: %w", err)
	}
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return "", fmt.Errorf("parse public key blob: %w", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), nil
}

// shellQuote wraps a value in single quotes for POSIX shells. The input is
// already validated as an authorized key, so this is defense in depth.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
