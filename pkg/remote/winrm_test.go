package remote

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grain/pkg/errorx"
)

func TestNewWinRMClient_Defaults(t *testing.T) {
	client, endpoint, err := NewWinRMClient(WinRMConfig{
		Host:     "127.0.0.1",
		User:     "Administrator",
		Password: "secret",
	})
	require.NoError(t, err)
	require.NotNil(t, client)
	require.NotNil(t, endpoint)
	assert.Equal(t, "127.0.0.1", endpoint.Host)
	assert.Equal(t, DefaultWinRMHTTPPort, endpoint.Port)
	assert.False(t, endpoint.HTTPS)
	assert.Equal(t, DefaultWinRMTimeout, endpoint.Timeout)
}

func TestNewWinRMClient_TLSPortAndExplicitPort(t *testing.T) {
	t.Run("tls defaults to https port", func(t *testing.T) {
		_, endpoint, err := NewWinRMClient(WinRMConfig{
			Host: "127.0.0.1", User: "u", Password: "p", UseTLS: true,
		})
		require.NoError(t, err)
		assert.Equal(t, DefaultWinRMHTTPSPort, endpoint.Port)
		assert.True(t, endpoint.HTTPS)
	})

	t.Run("explicit port wins", func(t *testing.T) {
		_, endpoint, err := NewWinRMClient(WinRMConfig{
			Host: "127.0.0.1", User: "u", Password: "p", Port: 1234,
		})
		require.NoError(t, err)
		assert.Equal(t, 1234, endpoint.Port)
		assert.False(t, endpoint.HTTPS)
	})

	t.Run("custom timeout", func(t *testing.T) {
		_, endpoint, err := NewWinRMClient(WinRMConfig{
			Host: "127.0.0.1", User: "u", Password: "p", Timeout: 5 * time.Second,
		})
		require.NoError(t, err)
		assert.Equal(t, 5*time.Second, endpoint.Timeout)
	})
}

func TestNewWinRMClient_Transports(t *testing.T) {
	t.Run("plaintext maps to basic", func(t *testing.T) {
		client, _, err := NewWinRMClient(WinRMConfig{
			Host: "127.0.0.1", User: "u", Password: "p", Transport: "plaintext",
		})
		require.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("ntlm", func(t *testing.T) {
		client, _, err := NewWinRMClient(WinRMConfig{
			Host: "127.0.0.1", User: "u", Password: "p", Transport: "NTLM",
		})
		require.NoError(t, err)
		assert.NotNil(t, client)
	})
}

func TestNewWinRMClient_Errors(t *testing.T) {
	tests := []struct {
		name string
		cfg  WinRMConfig
		code errorx.BizCode
	}{
		{
			name: "missing host",
			cfg:  WinRMConfig{User: "u", Password: "p"},
			code: errorx.CodeConfigError,
		},
		{
			name: "missing user",
			cfg:  WinRMConfig{Host: "127.0.0.1", Password: "p"},
			code: errorx.CodeConfigError,
		},
		{
			name: "unsupported transport",
			cfg:  WinRMConfig{Host: "127.0.0.1", User: "u", Password: "p", Transport: "unknown"},
			code: errorx.CodeProtocolUnsupported,
		},
		{
			name: "kerberos unsupported",
			cfg:  WinRMConfig{Host: "127.0.0.1", User: "u", Password: "p", Transport: "kerberos"},
			code: errorx.CodeProtocolUnsupported,
		},
		{
			name: "cert without certificates",
			cfg:  WinRMConfig{Host: "127.0.0.1", User: "u", Transport: "cert"},
			code: errorx.CodeConfigError,
		},
		{
			name: "basic without password",
			cfg:  WinRMConfig{Host: "127.0.0.1", User: "u"},
			code: errorx.CodeConfigError,
		},
		{
			name: "ntlm without password",
			cfg:  WinRMConfig{Host: "127.0.0.1", User: "u", Transport: "ntlm"},
			code: errorx.CodeConfigError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, endpoint, err := NewWinRMClient(tt.cfg)
			require.Error(t, err)
			assert.Nil(t, client)
			assert.Nil(t, endpoint)
			assert.True(t, errorx.IsCode(err, tt.code), "unexpected error: %v", err)
		})
	}
}

func TestEndpointAddress(t *testing.T) {
	assert.Equal(t, "http://127.0.0.1:5985", EndpointAddress("127.0.0.1", 5985, false))
	assert.Equal(t, "https://[::1]:5986", EndpointAddress("::1", 5986, true))
}
