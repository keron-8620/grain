package common

import (
	"context"
	"fmt"
	"path/filepath"

	"emperror.dev/errors"

	"grain/internal/conf"
	"grain/pkg/serializer"
)

const (
	ProtocolSSH   = "ssh"
	ProtocolWinRM = "winrm"

	OsTypeLinux   = "linux"
	OsTypeWindows = "windows"
)

type AnsibleHostVars struct {
	HostID                   uint64 `json:"host_id" yaml:"host_id"`
	AnsibleHost              string `json:"ansible_host" yaml:"ansible_host"`
	AnsiblePort              uint16 `json:"ansible_port" yaml:"ansible_port"`
	AnsibleUser              string `json:"ansible_user" yaml:"ansible_user"`
	AnsiblePythonInterpreter string `json:"ansible_python_interpreter,omitempty" yaml:"ansible_python_interpreter,omitempty"`
	AnsibleConnection        string `json:"ansible_connection,omitempty" yaml:"ansible_connection,omitempty"`
	AnsibleShellType         string `json:"ansible_shell_type,omitempty" yaml:"ansible_shell_type,omitempty"`
	AnsibleOSFamily          string `json:"ansible_os_family,omitempty" yaml:"ansible_os_family,omitempty"`
	AnsibleWinRMTransport    string `json:"ansible_winrm_transport,omitempty" yaml:"ansible_winrm_transport,omitempty"`
	AnsibleWinRMScheme       string `json:"ansible_winrm_scheme,omitempty" yaml:"ansible_winrm_scheme,omitempty"`
	AnsibleWinRMCertValidate string `json:"ansible_winrm_server_cert_validation,omitempty" yaml:"ansible_winrm_server_cert_validation,omitempty"`
	// AnsiblePassword is retained for compatibility but is never populated by
	// this service: remote execution is passwordless (SSH key / WinRM cert).
	AnsiblePassword          string `json:"ansible_password,omitempty" yaml:"ansible_password,omitempty"`
	AnsibleSSHPrivateKeyFile string `json:"ansible_ssh_private_key_file,omitempty" yaml:"ansible_ssh_private_key_file,omitempty"`
	// AnsibleSSHHostKey pins the SSH server host key captured at onboarding.
	AnsibleSSHHostKey string `json:"ansible_ssh_host_key,omitempty" yaml:"ansible_ssh_host_key,omitempty"`
	// Certificate file paths, not PEM contents: host_vars must not carry secrets.
	AnsibleWinRMCertPath string `json:"ansible_winrm_cert_path,omitempty" yaml:"ansible_winrm_cert_path,omitempty"`
	AnsibleWinRMKeyPath  string `json:"ansible_winrm_key_path,omitempty" yaml:"ansible_winrm_key_path,omitempty"`
	// Deprecated: legacy inline PEM fields, read only for backward compatibility.
	AnsibleWinRMCertPEM    string `json:"ansible_winrm_cert_pem,omitempty" yaml:"ansible_winrm_cert_pem,omitempty"`
	AnsibleWinRMCertKeyPEM string `json:"ansible_winrm_cert_key_pem,omitempty" yaml:"ansible_winrm_cert_key_pem,omitempty"`
}

func AnsibleHostVarPath(hostID uint64) string {
	return filepath.Join(conf.StorageDir, "host_vars", fmt.Sprintf("host_%d.yaml", hostID))
}

func LoadAnsibleHostVars(ctx context.Context, hostID uint64) (*AnsibleHostVars, *serializer.ReadResult, error) {
	path := AnsibleHostVarPath(hostID)
	var hv AnsibleHostVars
	res, err := serializer.ReadYAML(path, &hv, serializer.WithContext(ctx))
	if err != nil {
		return nil, res, errors.WithMessagef(err, "load ansible host vars, hostID=%d", hostID)
	}
	return &hv, res, nil
}

func DumpAnsibleHostVars(ctx context.Context, hv *AnsibleHostVars) (*serializer.WriteResult, error) {
	if hv == nil {
		return nil, errors.New("AnsibleHostVars is nil")
	}
	path := AnsibleHostVarPath(hv.HostID)

	res, err := serializer.WriteYAML(path, hv,
		serializer.WithContext(ctx),
		serializer.WithAtomic(true),
		// Host vars can contain credentials (passwords or client keys).
		serializer.WithFileMode(0o600),
		serializer.WithDirMode(0o700),
	)
	if err != nil {
		return res, errors.WithMessagef(err, "dump ansible host vars, hostID=%d", hv.HostID)
	}
	return res, nil
}
