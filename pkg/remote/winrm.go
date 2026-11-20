package remote

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/masterzen/winrm"

	"grain/pkg/errorx"
)

// WinRMConfig describes one WinRM client. Transport names match the values used
// by pywinrm/Ansible for ansible_winrm_transport.
type WinRMConfig struct {
	Host string
	Port int
	User string
	// Password is required for basic, ntlm, negotiate and credssp. It is not
	// required for cert authentication.
	Password string
	// UseTLS selects HTTPS. Cert authentication always forces TLS.
	UseTLS bool
	// Insecure skips server certificate validation.
	Insecure bool
	// CACert optionally verifies a private WinRM server certificate (PEM).
	CACert []byte
	// ClientCert and ClientKey are the mutual-TLS client certificate and key
	// (PEM), required when Transport is "cert".
	ClientCert []byte
	ClientKey  []byte
	// Transport is one of basic, plaintext, ntlm, negotiate, cert, credssp.
	// Empty means basic.
	Transport string
	// Timeout bounds the WinRM response header wait. Zero means
	// DefaultWinRMTimeout.
	Timeout time.Duration
}

// NewWinRMClient builds a WinRM client and returns its endpoint so callers can
// log the effective scheme/host/port. It does not connect; the first command
// opens the shell.
func NewWinRMClient(cfg WinRMConfig) (*winrm.Client, *winrm.Endpoint, error) {
	host := strings.TrimSpace(cfg.Host)
	user := strings.TrimSpace(cfg.User)
	if host == "" || user == "" {
		return nil, nil, errorx.CodeConfigError.Error("WinRM主机信息不完整，缺少主机地址或用户名")
	}

	transport := strings.ToLower(strings.TrimSpace(cfg.Transport))
	switch transport {
	case "", "basic", "plaintext":
		transport = "basic"
	case "ntlm", "negotiate":
		transport = "ntlm"
	case "cert":
		if len(cfg.ClientCert) == 0 || len(cfg.ClientKey) == 0 {
			return nil, nil, errorx.CodeConfigError.Error(
				"WinRM cert 认证需要配置客户端证书与私钥")
		}
	case "credssp":
	case "kerberos":
		return nil, nil, errorx.CodeProtocolUnsupported.Error("暂不支持 WinRM kerberos 认证")
	default:
		return nil, nil, errorx.CodeProtocolUnsupported.Errorf("不支持的WinRM认证方式: %s", transport)
	}

	// Certificate authentication requires TLS and therefore defaults to the
	// HTTPS port when the caller did not pin a port.
	useTLS := cfg.UseTLS || transport == "cert"
	port := cfg.Port
	if port <= 0 || port > 65535 {
		if useTLS {
			port = DefaultWinRMHTTPSPort
		} else {
			port = DefaultWinRMHTTPPort
		}
	}

	if transport != "cert" && cfg.Password == "" {
		return nil, nil, errorx.CodeConfigError.Errorf("WinRM认证方式 %s 需要配置密码", transport)
	}

	params := *winrm.DefaultParameters
	switch transport {
	case "basic":
		// The default winrm transport uses HTTP Basic authentication.
	case "ntlm":
		params.TransportDecorator = func() winrm.Transporter { return &winrm.ClientNTLM{} }
	case "cert":
		params.TransportDecorator = func() winrm.Transporter { return &winrm.ClientAuthRequest{} }
	case "credssp":
		params.TransportDecorator = func() winrm.Transporter { return winrm.NewClientCredSSP() }
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultWinRMTimeout
	}

	endpoint := winrm.NewEndpoint(
		host,
		port,
		useTLS,
		cfg.Insecure,
		cfg.CACert,
		cfg.ClientCert,
		cfg.ClientKey,
		timeout,
	)

	client, err := winrm.NewClientWithParameters(endpoint, user, cfg.Password, &params)
	if err != nil {
		return nil, nil, errorx.Wrapf(err, errorx.CodeWinRMConnectionFailed,
			"创建WinRM客户端失败: %s", EndpointAddress(host, port, useTLS))
	}
	return client, endpoint, nil
}

// EndpointAddress renders the effective WinRM endpoint for logs and errors.
func EndpointAddress(host string, port int, useTLS bool) string {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port))
}
