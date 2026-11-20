package cmdb

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"grain/internal/biz/common"
	"grain/internal/conf"
	"grain/pkg/db"
	"grain/pkg/errorx"
)

// mockHostRepo is an in-memory implementation of HostRepo for unit tests.
type mockHostRepo struct {
	mu      sync.RWMutex
	nextID  uint64
	hosts   map[uint64]*Host
	findErr error
	saveErr error
}

func newMockHostRepo() *mockHostRepo {
	return &mockHostRepo{
		nextID: 1,
		hosts:  make(map[uint64]*Host),
	}
}

func cloneHost(h *Host) *Host {
	if h == nil {
		return nil
	}
	cp := *h
	return &cp
}

func (m *mockHostRepo) Create(_ context.Context, host *Host) (*Host, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return nil, m.saveErr
	}
	cp := cloneHost(host)
	cp.ID = m.nextID
	m.nextID++
	cp.CreatedAt = time.Now()
	cp.UpdatedAt = cp.CreatedAt
	m.hosts[cp.ID] = cp
	return cloneHost(cp), nil
}

func (m *mockHostRepo) Update(_ context.Context, host *Host) (*Host, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return nil, m.saveErr
	}
	existing, ok := m.hosts[host.ID]
	if !ok {
		return nil, errors.New("record not found")
	}
	cp := cloneHost(host)
	cp.CreatedAt = existing.CreatedAt
	cp.UpdatedAt = time.Now()
	m.hosts[cp.ID] = cp
	return cloneHost(cp), nil
}

func (m *mockHostRepo) Delete(_ context.Context, id uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return m.saveErr
	}
	delete(m.hosts, id)
	return nil
}

func (m *mockHostRepo) FindByID(_ context.Context, id uint64) (*Host, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.findErr != nil {
		return nil, m.findErr
	}
	return cloneHost(m.hosts[id]), nil
}

func (m *mockHostRepo) FindByIDs(_ context.Context, ids []uint64) ([]Host, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.findErr != nil {
		return nil, m.findErr
	}
	var out []Host
	for _, id := range ids {
		if h, ok := m.hosts[id]; ok {
			out = append(out, *cloneHost(h))
		}
	}
	return out, nil
}

func (m *mockHostRepo) List(_ context.Context, _ db.ListOptions) ([]Host, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.findErr != nil {
		return nil, 0, m.findErr
	}
	out := make([]Host, 0, len(m.hosts))
	for _, h := range m.hosts {
		out = append(out, *cloneHost(h))
	}
	return out, int64(len(out)), nil
}

func (m *mockHostRepo) ExistsByHostIPPortUser(_ context.Context, ip string, port uint16, user string, filters []db.ListFilter) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.findErr != nil {
		return false, m.findErr
	}
	var excludeID uint64
	for _, f := range filters {
		if f.Field == "id" && f.Op == db.ListFilterNotEquals {
			if id, ok := f.Value.(uint64); ok {
				excludeID = id
			}
		}
	}
	for _, h := range m.hosts {
		if excludeID != 0 && h.ID == excludeID {
			continue
		}
		if h.HostIP == ip && h.HostPort == port && h.HostUser == user {
			return true, nil
		}
	}
	return false, nil
}

// generateTestSSHKeyPair creates an ed25519 SSH key pair and returns both the
// full authorized_keys line and the bare base64 wire payload.
func generateTestSSHKeyPair(t *testing.T) (authLine string, bareB64 string, signer ssh.Signer) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)

	signer, err = ssh.NewSignerFromKey(priv)
	require.NoError(t, err)

	authLine = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	bareB64 = base64.StdEncoding.EncodeToString(sshPub.Marshal())
	return authLine, bareB64, signer
}

// startMockSSHServer spins up an in-process SSH server that records received exec commands.
func startMockSSHServer(t *testing.T, serverSigner ssh.Signer, failExec bool) (ip string, port uint16, commands *[]string) {
	t.Helper()
	var mu sync.Mutex
	var cmds []string

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, _ []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
		PublicKeyCallback: func(_ ssh.ConnMetadata, _ ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	cfg.AddHostKey(serverSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		for {
			rawConn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)

				for newChan := range chans {
					if newChan.ChannelType() != "session" {
						_ = newChan.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					ch, requests, err := newChan.Accept()
					if err != nil {
						continue
					}
					go func(channel ssh.Channel, in <-chan *ssh.Request) {
						defer func() { _ = channel.Close() }()
						for req := range in {
							if req.Type == "exec" && len(req.Payload) >= 4 {
								cmdLen := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
								if len(req.Payload) >= 4+cmdLen {
									mu.Lock()
									cmds = append(cmds, string(req.Payload[4:4+cmdLen]))
									mu.Unlock()
								}
								if req.WantReply {
									_ = req.Reply(true, nil)
								}
								exitStatus := uint32(0)
								if failExec {
									_, _ = io.WriteString(channel.Stderr(), "permission denied writing authorized_keys")
									exitStatus = 1
								}
								statusPayload := []byte{
									byte(exitStatus >> 24),
									byte(exitStatus >> 16),
									byte(exitStatus >> 8),
									byte(exitStatus),
								}
								_, _ = channel.SendRequest("exit-status", false, statusPayload)
								return
							}
							if req.WantReply {
								_ = req.Reply(false, nil)
							}
						}
					}(ch, requests)
				}
			}(rawConn)
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()
	})

	hostStr, portStr, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	p, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	return hostStr, uint16(p), &cmds
}

// generateTestWinRMCerts writes a self-signed CA + client cert/key into t.TempDir().
func generateTestWinRMCerts(t *testing.T) (caPEM []byte, clientCertPath, clientKeyPath string) {
	t.Helper()
	dir := t.TempDir()

	caPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test WinRM CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caPriv.PublicKey, caPriv)
	require.NoError(t, err)
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	clientPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	clientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "winrm-admin"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTmpl, caTmpl, &clientPriv.PublicKey, caPriv)
	require.NoError(t, err)

	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientPriv)})

	clientCertPath = filepath.Join(dir, "client.crt")
	clientKeyPath = filepath.Join(dir, "client.key")
	require.NoError(t, os.WriteFile(clientCertPath, clientCertPEM, 0o600))
	require.NoError(t, os.WriteFile(clientKeyPath, clientKeyPEM, 0o600))

	return caPEM, clientCertPath, clientKeyPath
}

func TestHostUseCase_Create(t *testing.T) {
	ctx := context.Background()
	authLine, bareB64, signer := generateTestSSHKeyPair(t)

	t.Run("validation errors", func(t *testing.T) {
		uc := NewHostUseCase(newMockHostRepo(), nil, time.Second, nil, nil)

		_, err := uc.Create(ctx, nil)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))

		_, err = uc.Create(ctx, &Host{HostIP: "10.0.0.1", HostUser: "root"})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))

		_, err = uc.Create(ctx, &Host{Name: "web-1", HostUser: "root"})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))

		_, err = uc.Create(ctx, &Host{Name: "web-1", HostIP: "10.0.0.1"})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))

		_, err = uc.Create(ctx, &Host{Name: "web-1", HostIP: "10.0.0.1", HostUser: "root", Protocol: "telnet"})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeProtocolUnsupported))
	})

	t.Run("skips key deployment when no keys configured", func(t *testing.T) {
		repo := newMockHostRepo()
		uc := NewHostUseCase(repo, nil, time.Second, nil, nil)

		created, err := uc.Create(ctx, &Host{
			Name:     "linux-node-1",
			HostIP:   "10.0.0.1",
			HostUser: "ansible",
		})
		require.NoError(t, err)
		assert.Equal(t, uint64(1), created.ID)
		assert.Equal(t, common.ProtocolSSH, created.Protocol)
		assert.Equal(t, uint16(defaultSSHPort), created.HostPort)
		assert.Equal(t, common.OsTypeLinux, created.OSType)
	})

	t.Run("duplicate host connection rejected", func(t *testing.T) {
		repo := newMockHostRepo()
		uc := NewHostUseCase(repo, nil, time.Second, nil, nil)

		_, err := uc.Create(ctx, &Host{Name: "node-1", HostIP: "10.0.0.1", HostUser: "root"})
		require.NoError(t, err)

		_, err = uc.Create(ctx, &Host{Name: "node-1-dup", HostIP: "10.0.0.1", HostUser: "root"})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeDuplicatedKey))
	})

	t.Run("windows with ssh protocol is rejected", func(t *testing.T) {
		repo := newMockHostRepo()
		uc := NewHostUseCase(repo, nil, time.Second, ssh.Password("pass"), []string{authLine})

		_, err := uc.Create(ctx, &Host{
			Name:     "win-bad-proto",
			HostIP:   "10.0.0.2",
			HostUser: "Administrator",
			Protocol: common.ProtocolSSH,
			OSType:   common.OsTypeWindows,
		})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))
		assert.Contains(t, err.Error(), "windows机器不支持ssh")
	})

	t.Run("windows winrm skips verification when no client cert configured", func(t *testing.T) {
		repo := newMockHostRepo()
		// Even when SSH keys are configured, WinRM should not fail when WinRM certs are unset.
		uc := NewHostUseCase(repo, nil, time.Second, ssh.Password("pass"), []string{authLine})

		created, err := uc.Create(ctx, &Host{
			Name:     "win-node-1",
			HostIP:   "10.0.0.2",
			HostUser: "Administrator",
			Protocol: common.ProtocolWinRM,
		})
		require.NoError(t, err)
		assert.Equal(t, common.ProtocolWinRM, created.Protocol)
		assert.Equal(t, uint16(defaultWinRMPort), created.HostPort)
		assert.Equal(t, common.OsTypeWindows, created.OSType)
	})

	t.Run("ssh onboarding deploys deduplicated keys and persists host", func(t *testing.T) {
		ip, port, cmds := startMockSSHServer(t, signer, false)
		repo := newMockHostRepo()
		// Pass duplicate keys in both full line and bare base64 forms.
		uc := NewHostUseCase(repo, nil, 5*time.Second, ssh.Password("secret"), []string{authLine, bareB64})

		created, err := uc.Create(ctx, &Host{
			Name:     "ssh-real-node",
			HostIP:   ip,
			HostPort: port,
			HostUser: "deploy",
		})
		require.NoError(t, err)
		assert.Equal(t, uint64(1), created.ID)
		require.Len(t, *cmds, 1)
		assert.Contains(t, (*cmds)[0], authLine)
		assert.Equal(t, 2, strings.Count((*cmds)[0], authLine))

		// Onboarding pins the server host key for later verification.
		expectedHostKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
		assert.Equal(t, expectedHostKey, created.HostKey)
		stored, err := repo.FindByID(ctx, created.ID)
		require.NoError(t, err)
		assert.Equal(t, expectedHostKey, stored.HostKey)

		// Re-pinning an existing host (rebuild/key rotation) succeeds and keeps
		// the same key.
		refreshed, err := uc.RefreshHostKey(ctx, created.ID)
		require.NoError(t, err)
		assert.Equal(t, expectedHostKey, refreshed.HostKey)
	})

	t.Run("ssh onboarding failure does not persist host", func(t *testing.T) {
		ip, port, _ := startMockSSHServer(t, signer, true)
		repo := newMockHostRepo()
		uc := NewHostUseCase(repo, nil, 5*time.Second, ssh.Password("secret"), []string{authLine})

		_, err := uc.Create(ctx, &Host{
			Name:     "ssh-fail-node",
			HostIP:   ip,
			HostPort: port,
			HostUser: "deploy",
		})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeSSHKeyDeployFailed))

		hosts, total, listErr := repo.List(ctx, db.ListOptions{})
		require.NoError(t, listErr)
		assert.Zero(t, total)
		assert.Empty(t, hosts)
	})

	t.Run("winrm mutual tls onboarding with client certificate", func(t *testing.T) {
		caPEM, certPath, keyPath := generateTestWinRMCerts(t)

		caPool := x509.NewCertPool()
		require.True(t, caPool.AppendCertsFromPEM(caPEM))

		// Mock HTTPS WinRM endpoint verifying client certificate presence and WS-Man actions.
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, "client certificate required", http.StatusUnauthorized)
				return
			}
			bodyBytes, _ := io.ReadAll(r.Body)
			reqBody := string(bodyBytes)

			var respAction, respBody string
			switch {
			case strings.Contains(reqBody, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"):
				respAction = "http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse"
				respBody = `<rsp:Shell xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><rsp:ShellId>11111111-1111-1111-1111-111111111111</rsp:ShellId></rsp:Shell>`
			case strings.Contains(reqBody, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command"):
				respAction = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandResponse"
				respBody = `<rsp:CommandResponse xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><rsp:CommandId>22222222-2222-2222-2222-222222222222</rsp:CommandId></rsp:CommandResponse>`
			case strings.Contains(reqBody, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive"):
				respAction = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReceiveResponse"
				respBody = `<rsp:ReceiveResponse xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
      <rsp:Stream Name="stdout" CommandId="22222222-2222-2222-2222-222222222222" End="true">d2luLWFkbWluCg==</rsp:Stream>
      <rsp:CommandState CommandId="22222222-2222-2222-2222-222222222222" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
        <rsp:ExitCode>0</rsp:ExitCode>
      </rsp:CommandState>
    </rsp:ReceiveResponse>`
			case strings.Contains(reqBody, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"):
				respAction = "http://schemas.xmlsoap.org/ws/2004/09/transfer/DeleteResponse"
				respBody = ``
			default:
				http.Error(w, "unknown wsman action", http.StatusBadRequest)
				return
			}

			w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
			_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
  <s:Header>
    <a:Action>%s</a:Action>
  </s:Header>
  <s:Body>%s</s:Body>
</s:Envelope>`, respAction, respBody)
		}))
		srv.TLS = &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  caPool,
		}
		srv.StartTLS()
		defer srv.Close()

		hostStr, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
		require.NoError(t, err)
		portNum, err := strconv.Atoi(portStr)
		require.NoError(t, err)

		repo := newMockHostRepo()
		uc := NewHostUseCase(repo, nil, 5*time.Second, nil, nil, WithWinRMConfig(WinRMConfig{
			UseTLS:         true,
			Insecure:       true, // httptest leaf cert uses 127.0.0.1 / example.com
			ClientCertPath: certPath,
			ClientKeyPath:  keyPath,
		}))

		created, err := uc.Create(ctx, &Host{
			Name:     "win-mtls-node",
			HostIP:   hostStr,
			HostPort: uint16(portNum),
			HostUser: "Administrator",
			Protocol: common.ProtocolWinRM,
		})
		require.NoError(t, err)
		assert.Equal(t, uint64(1), created.ID)
		assert.Equal(t, common.OsTypeWindows, created.OSType)
	})

	t.Run("winrm invalid cert config returns config error", func(t *testing.T) {
		repo := newMockHostRepo()
		uc := NewHostUseCase(repo, nil, time.Second, nil, nil, WithWinRMConfig(WinRMConfig{
			ClientCertPath: "/nonexistent/client.crt",
			ClientKeyPath:  "/nonexistent/client.key",
		}))

		_, err := uc.Create(ctx, &Host{
			Name:     "win-bad-cert",
			HostIP:   "10.0.0.3",
			HostUser: "Administrator",
			Protocol: common.ProtocolWinRM,
		})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeConfigError))
	})
}

func TestHostUseCase_UpdateDeleteGetList(t *testing.T) {
	ctx := context.Background()
	authLine, _, signer := generateTestSSHKeyPair(t)
	ip, port, cmds := startMockSSHServer(t, signer, false)

	repo := newMockHostRepo()
	uc := NewHostUseCase(repo, nil, 5*time.Second, ssh.Password("secret"), []string{authLine})

	created, err := uc.Create(ctx, &Host{
		Name:     "app-1",
		HostIP:   ip,
		HostPort: port,
		HostUser: "ops",
	})
	require.NoError(t, err)
	require.Len(t, *cmds, 1)

	t.Run("update metadata only does not redeploy key", func(t *testing.T) {
		updated, err := uc.Update(ctx, &Host{
			ID:       created.ID,
			Name:     "app-1-renamed",
			HostIP:   ip,
			HostPort: port,
			HostUser: "ops",
			Remark:   "updated remark",
		})
		require.NoError(t, err)
		assert.Equal(t, "app-1-renamed", updated.Name)
		assert.Len(t, *cmds, 1) // no additional SSH command executed
	})

	t.Run("update connection user redeploys key", func(t *testing.T) {
		updated, err := uc.Update(ctx, &Host{
			ID:       created.ID,
			Name:     "app-1-renamed",
			HostIP:   ip,
			HostPort: port,
			HostUser: "ops-new",
		})
		require.NoError(t, err)
		assert.Equal(t, "ops-new", updated.HostUser)
		assert.Len(t, *cmds, 2)
	})

	t.Run("get, getByIDs, list and delete", func(t *testing.T) {
		got, err := uc.Get(ctx, created.ID)
		require.NoError(t, err)
		assert.Equal(t, "ops-new", got.HostUser)

		batch, err := uc.GetByIDs(ctx, []uint64{created.ID})
		require.NoError(t, err)
		require.Len(t, batch, 1)

		list, total, err := uc.List(ctx, db.ListOptions{})
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		assert.Len(t, list, 1)

		require.NoError(t, uc.Delete(ctx, created.ID))

		_, err = uc.Get(ctx, created.ID)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})
}

func setCMDBHostVarsStorage(t *testing.T) string {
	t.Helper()

	oldStorageDir := conf.StorageDir
	conf.StorageDir = t.TempDir()
	t.Cleanup(func() { conf.StorageDir = oldStorageDir })
	return conf.StorageDir
}

func TestHostUseCase_AnsibleHostVarsLifecycle(t *testing.T) {
	setCMDBHostVarsStorage(t)
	ctx := context.Background()

	repo := newMockHostRepo()
	uc := NewHostUseCase(repo, nil, time.Second, nil, nil)

	created, err := uc.Create(ctx, &Host{
		Name:     "node-1",
		HostIP:   "10.1.2.3",
		HostUser: "ansible",
		PyPath:   "/usr/bin/python3",
	})
	require.NoError(t, err)

	vars, _, err := common.LoadAnsibleHostVars(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, vars.HostID)
	assert.Equal(t, "10.1.2.3", vars.AnsibleHost)
	assert.Equal(t, uint16(defaultSSHPort), vars.AnsiblePort)
	assert.Equal(t, "ansible", vars.AnsibleUser)
	assert.Equal(t, common.ProtocolSSH, vars.AnsibleConnection)
	assert.Equal(t, "/usr/bin/python3", vars.AnsiblePythonInterpreter)
	assert.Equal(t, common.OsTypeLinux, vars.AnsibleOSFamily)
	assert.Equal(t, "sh", vars.AnsibleShellType)

	info, err := os.Stat(common.AnsibleHostVarPath(created.ID))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	created.PyPath = "/usr/bin/python3.12"
	created.HostUser = "ansible-2"
	_, err = uc.Update(ctx, created)
	require.NoError(t, err)

	vars, _, err = common.LoadAnsibleHostVars(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "ansible-2", vars.AnsibleUser)
	assert.Equal(t, "/usr/bin/python3.12", vars.AnsiblePythonInterpreter)

	require.NoError(t, uc.Delete(ctx, created.ID))
	_, err = os.Stat(common.AnsibleHostVarPath(created.ID))
	assert.True(t, os.IsNotExist(err))
}

func TestHostUseCase_BuildAnsibleHostVars_SSH(t *testing.T) {
	uc := NewHostUseCase(newMockHostRepo(), nil, time.Second, nil, nil,
		WithSSHPrivateKeyPath("/etc/grain/ssh/id_ed25519"))

	vars, err := uc.buildAnsibleHostVars(&Host{
		ID:       8,
		HostIP:   "10.0.0.8",
		HostPort: 22,
		HostUser: "deploy",
		Protocol: common.ProtocolSSH,
		OSType:   common.OsTypeLinux,
		HostKey:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey",
	})
	require.NoError(t, err)
	assert.Equal(t, "/etc/grain/ssh/id_ed25519", vars.AnsibleSSHPrivateKeyFile)
	assert.Equal(t, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey", vars.AnsibleSSHHostKey)
	assert.Empty(t, vars.AnsiblePassword, "host vars must never contain a password")
	assert.Empty(t, vars.AnsibleWinRMCertPEM)
}

func TestHostUseCase_BuildAnsibleHostVars_WinRM(t *testing.T) {
	_, certPath, keyPath := generateTestWinRMCerts(t)
	uc := NewHostUseCase(newMockHostRepo(), nil, time.Second, nil, nil, WithWinRMConfig(WinRMConfig{
		UseTLS:         true,
		Insecure:       true,
		ClientCertPath: certPath,
		ClientKeyPath:  keyPath,
	}))

	vars, err := uc.buildAnsibleHostVars(&Host{
		ID:       9,
		HostIP:   "10.0.0.9",
		HostPort: defaultWinRMHTTPSPort,
		HostUser: "Administrator",
		Protocol: common.ProtocolWinRM,
		OSType:   common.OsTypeWindows,
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(9), vars.HostID)
	assert.Equal(t, common.ProtocolWinRM, vars.AnsibleConnection)
	assert.Equal(t, "https", vars.AnsibleWinRMScheme)
	assert.Equal(t, "ignore", vars.AnsibleWinRMCertValidate)
	assert.Equal(t, "cert", vars.AnsibleWinRMTransport)
	assert.Equal(t, "powershell", vars.AnsibleShellType)

	assert.Equal(t, certPath, vars.AnsibleWinRMCertPath)
	assert.Equal(t, keyPath, vars.AnsibleWinRMKeyPath)
	assert.Empty(t, vars.AnsibleWinRMCertPEM, "host vars must not embed certificate material")
	assert.Empty(t, vars.AnsibleWinRMCertKeyPEM, "host vars must not embed private key material")
	assert.Empty(t, vars.AnsiblePassword, "host vars must never contain a password")
}

func TestHostUseCase_AnsibleHostVarsExportFailureRollsBack(t *testing.T) {
	ctx := context.Background()

	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))

	oldStorageDir := conf.StorageDir
	conf.StorageDir = blocker
	t.Cleanup(func() { conf.StorageDir = oldStorageDir })

	repo := newMockHostRepo()
	uc := NewHostUseCase(repo, nil, time.Second, nil, nil)

	_, err := uc.Create(ctx, &Host{Name: "no-cache", HostIP: "10.0.0.10", HostUser: "root"})
	require.Error(t, err)
	assert.True(t, errorx.IsCode(err, errorx.CodeExternalError))

	hosts, total, listErr := repo.List(ctx, db.ListOptions{})
	require.NoError(t, listErr)
	assert.Zero(t, total)
	assert.Empty(t, hosts)
}

func TestHostVarsNeverContainSecrets(t *testing.T) {
	oldStorage := conf.StorageDir
	conf.StorageDir = t.TempDir()
	t.Cleanup(func() { conf.StorageDir = oldStorage })

	uc := NewHostUseCase(newMockHostRepo(), nil, time.Second, nil, nil,
		WithSSHPrivateKeyPath("/etc/grain/id_ed25519"))

	host := &Host{
		ID:       77,
		HostIP:   "10.0.0.77",
		HostPort: 22,
		HostUser: "deploy",
		Protocol: common.ProtocolSSH,
		OSType:   common.OsTypeLinux,
		HostKey:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey",
	}
	require.NoError(t, uc.syncAnsibleHostVars(context.Background(), host))

	data, err := os.ReadFile(common.AnsibleHostVarPath(77))
	require.NoError(t, err)
	body := string(data)
	assert.Contains(t, body, "/etc/grain/id_ed25519")
	assert.Contains(t, body, "ssh-ed25519")
	assert.NotContains(t, body, "ansible_password")
	assert.NotContains(t, body, "PRIVATE KEY")
}

func TestHostUseCase_ResyncHostVarsRemovesLegacySecrets(t *testing.T) {
	oldStorage := conf.StorageDir
	conf.StorageDir = t.TempDir()
	t.Cleanup(func() { conf.StorageDir = oldStorage })

	repo := newMockHostRepo()
	host, err := repo.Create(context.Background(), &Host{
		Name:     "legacy",
		HostIP:   "10.0.0.90",
		HostPort: 22,
		HostUser: "deploy",
		Protocol: common.ProtocolSSH,
		OSType:   common.OsTypeLinux,
	})
	require.NoError(t, err)

	legacy := "host_id: 1\nansible_host: 10.0.0.90\nansible_user: deploy\n" +
		"ansible_password: legacy-secret\nansible_winrm_cert_pem: '-----BEGIN CERTIFICATE-----'\n" +
		"ansible_winrm_cert_key_pem: '-----BEGIN PRIVATE KEY-----'\n"
	legacyPath := common.AnsibleHostVarPath(host.ID)
	require.NoError(t, os.MkdirAll(filepath.Dir(legacyPath), 0o700))
	require.NoError(t, os.WriteFile(legacyPath, []byte(legacy), 0o600))

	uc := NewHostUseCase(repo, nil, time.Second, nil, nil,
		WithSSHPrivateKeyPath("/etc/grain/id_ed25519"))
	n, err := uc.ResyncHostVars(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	data, err := os.ReadFile(common.AnsibleHostVarPath(host.ID))
	require.NoError(t, err)
	body := string(data)
	assert.NotContains(t, body, "ansible_password")
	assert.NotContains(t, body, "PRIVATE KEY")
	assert.NotContains(t, body, "BEGIN CERTIFICATE")
	assert.Contains(t, body, "/etc/grain/id_ed25519")
}
