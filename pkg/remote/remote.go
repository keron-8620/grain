// Package remote provides shared SSH and WinRM connection primitives used by
// host onboarding and script execution.
//
// It intentionally covers transport concerns only: resolving SSH credentials,
// dialing a connection, running a command in a session and building a WinRM
// client. Business-specific behavior such as command composition, script
// upload layout and working-directory semantics stays in the caller.
package remote

import "time"

const (
	// DefaultSSHPort is used when a host does not specify an SSH port.
	DefaultSSHPort = 22

	// DefaultWinRMHTTPPort is the standard WinRM HTTP listener port.
	DefaultWinRMHTTPPort = 5985

	// DefaultWinRMHTTPSPort is the standard WinRM HTTPS listener port.
	DefaultWinRMHTTPSPort = 5986

	// DefaultSSHTimeout bounds both the TCP dial and the SSH handshake.
	DefaultSSHTimeout = 30 * time.Second

	// DefaultWinRMTimeout bounds the WinRM response header wait. It stays
	// above the default 60s WS-Man operation timeout.
	DefaultWinRMTimeout = 90 * time.Second
)
