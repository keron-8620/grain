package remote

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestHostKeyMarshalParseFingerprint(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)

	line := MarshalHostKey(key)
	require.NotEmpty(t, line)
	assert.Contains(t, line, "ssh-ed25519")

	parsed, err := ParseHostKey(line)
	require.NoError(t, err)
	assert.Equal(t, line, MarshalHostKey(parsed))
	assert.Equal(t, ssh.FingerprintSHA256(key), HostKeyFingerprint(parsed))
	assert.NotEmpty(t, HostKeyFingerprint(key))
	assert.Empty(t, HostKeyFingerprint(nil))
	assert.Empty(t, MarshalHostKey(nil))

	_, err = ParseHostKey("")
	assert.Error(t, err)
	_, err = ParseHostKey("not-a-key")
	assert.Error(t, err)
}

func TestCaptureHostKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)

	var captured ssh.PublicKey
	callback := CaptureHostKey(&captured)
	require.NotNil(t, callback)

	require.NoError(t, callback("example.com:22", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}, key))
	assert.Equal(t, ssh.FingerprintSHA256(key), ssh.FingerprintSHA256(captured))
}
