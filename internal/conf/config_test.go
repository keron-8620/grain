package conf

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grain/pkg/cryptoutil"
	"grain/pkg/db"
)

func minimalBootstrap(t *testing.T) *Bootstrap {
	t.Helper()
	privateKey, _, err := cryptoutil.GenerateRSAKeyPair(2048)
	require.NoError(t, err)
	pemBytes, err := cryptoutil.MarshalPrivateKeyPKCS8PEM(privateKey)
	require.NoError(t, err)
	return &Bootstrap{
		Server: &ServerConfig{Host: "127.0.0.1", Port: 8080},
		Database: &db.DBConf{
			Type: "sqlite",
			Dsn:  "grain.db",
		},
		IAM: &IAMConfig{
			Token: TokenConfig{PrivateKey: string(pemBytes)},
		},
	}
}

func TestBootstrapValidate(t *testing.T) {
	t.Run("minimal config and defaults", func(t *testing.T) {
		bc := minimalBootstrap(t)
		require.NoError(t, bc.Validate())
		assert.NotNil(t, bc.Security)
		assert.NotNil(t, bc.Security.CORS)
		assert.NotNil(t, bc.Log)
	})

	t.Run("nil sections", func(t *testing.T) {
		var nilBC *Bootstrap
		assert.Error(t, nilBC.Validate())
		assert.Error(t, (&Bootstrap{}).Validate())

		bc := minimalBootstrap(t)
		bc.Server = nil
		assert.Error(t, bc.Validate())

		bc = minimalBootstrap(t)
		bc.Database = nil
		assert.Error(t, bc.Validate())
	})

	t.Run("database validation", func(t *testing.T) {
		bc := minimalBootstrap(t)
		bc.Database.Type = ""
		assert.Error(t, bc.Validate())

		bc = minimalBootstrap(t)
		bc.Database.Type = "oracle"
		assert.Error(t, bc.Validate())

		bc = minimalBootstrap(t)
		bc.Database.Type = "postgres"
		bc.Database.Dsn = ""
		assert.Error(t, bc.Validate(), "non-sqlite databases require a DSN")

		bc = minimalBootstrap(t)
		bc.Database.Type = "sqlite"
		bc.Database.Dsn = ""
		require.NoError(t, bc.Validate(), "sqlite may use an in-memory/empty DSN")
	})

	t.Run("server validation", func(t *testing.T) {
		bc := minimalBootstrap(t)
		bc.Server.Port = 0
		assert.Error(t, bc.Validate())

		bc = minimalBootstrap(t)
		bc.Server.Port = 70000
		assert.Error(t, bc.Validate())

		bc = minimalBootstrap(t)
		bc.Server.SSL.Enable = true
		assert.Error(t, bc.Validate())

		bc = minimalBootstrap(t)
		bc.Server.Rate.RPS = -1
		assert.Error(t, bc.Validate())

		bc = minimalBootstrap(t)
		bc.Server.Timeout.Request = -time.Second
		assert.Error(t, bc.Validate())
	})

	t.Run("redis requires address when enabled", func(t *testing.T) {
		bc := minimalBootstrap(t)
		bc.Redis = &RedisConfig{Enable: true}
		assert.Error(t, bc.Validate())

		bc.Redis.Addr = "127.0.0.1:6379"
		require.NoError(t, bc.Validate())
	})

	t.Run("login lockout validation", func(t *testing.T) {
		bc := minimalBootstrap(t)
		bc.IAM.Login.MaxFailedAttempts = 5
		assert.Error(t, bc.Validate(), "lock duration is required when lockout is enabled")

		bc.IAM.Login.LockDuration = 15 * time.Minute
		require.NoError(t, bc.Validate())

		bc.IAM.Login.MaxFailedAttempts = -1
		assert.Error(t, bc.Validate())

		bc = minimalBootstrap(t)
		bc.IAM.Login.LockDuration = -time.Minute
		assert.Error(t, bc.Validate())
	})

	t.Run("password strength level validation", func(t *testing.T) {
		for level := 0; level <= 3; level++ {
			bc := minimalBootstrap(t)
			bc.IAM.Password.StrengthLevel = level
			require.NoError(t, bc.Validate())
		}
		for _, level := range []int{-1, 4} {
			bc := minimalBootstrap(t)
			bc.IAM.Password.StrengthLevel = level
			assert.Error(t, bc.Validate())
		}
	})

	t.Run("refresh method must match access method", func(t *testing.T) {
		bc := minimalBootstrap(t)
		bc.IAM.Token.AccessMethod = "RS256"
		bc.IAM.Token.RefreshMethod = "RS512"
		assert.Error(t, bc.Validate())

		bc.IAM.Token.RefreshMethod = "RS256"
		require.NoError(t, bc.Validate())
	})

	t.Run("script repository validation", func(t *testing.T) {
		bc := minimalBootstrap(t)
		bc.Job = &JobConfig{ScriptRepo: &ScriptRepoConfig{Enable: true}}
		assert.Error(t, bc.Validate(), "url and dir are required when enabled")

		bc.Job.ScriptRepo.URL = "https://example.com/scripts.git"
		bc.Job.ScriptRepo.Dir = "data/scripts"
		bc.Job.ScriptRepo.AuthType = "kerberos"
		assert.Error(t, bc.Validate(), "unsupported auth type")

		bc.Job.ScriptRepo.AuthType = "http"
		require.NoError(t, bc.Validate())

		bc.Job.ScriptRepo.Timeout = -time.Second
		assert.Error(t, bc.Validate())
	})

	t.Run("signing key is required", func(t *testing.T) {
		bc := minimalBootstrap(t)
		bc.IAM.Token.PrivateKey = ""
		assert.Error(t, bc.Validate())

		bc = minimalBootstrap(t)
		bc.IAM.Token.AccessMethod = "HS256"
		assert.Error(t, bc.Validate(), "symmetric algorithms are not supported")
	})
}

func TestSigningMethod(t *testing.T) {
	method, err := SigningMethod("")
	require.NoError(t, err)
	assert.Equal(t, "RS256", method.Alg())

	method, err = SigningMethod("RS512")
	require.NoError(t, err)
	assert.Equal(t, "RS512", method.Alg())

	_, err = SigningMethod("none")
	assert.Error(t, err)
}

func TestBootstrapValidate_CMDBPasswordless(t *testing.T) {
	// Password-only onboarding cannot support passwordless execution.
	bc := minimalBootstrap(t)
	bc.CMDB = &CMDBConfig{SSHPassword: "secret"}
	assert.Error(t, bc.Validate())

	// Public-key onboarding also needs the execution private key.
	bc = minimalBootstrap(t)
	bc.CMDB = &CMDBConfig{PublicKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest"}}
	assert.Error(t, bc.Validate())

	// A private key satisfies both onboarding and execution.
	bc = minimalBootstrap(t)
	bc.CMDB = &CMDBConfig{SSHPrivateKey: "/etc/grain/id_ed25519"}
	require.NoError(t, bc.Validate())
}
