package oskeyring

import (
	"crypto/rand"
	"encoding/base64"
	"nidan-kai/keystore"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
)

// This ensures OsKeyring implements the keystore.Keystore interface.
var _ keystore.Keystore = OsKeyring{}

const (
	testService = "nidan-kai-test-service"
	testUser    = "nidan-kai-test-user"
)

// setupEnv sets environment variables for tests.
func setupEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SERVICE_NAME", testService)
	t.Setenv("OS_KEYRING_USER", testUser)
}

func Test_getEnv(t *testing.T) {
	t.Run("should return envs when set", func(t *testing.T) {
		t.Setenv("SERVICE_NAME", "my-service")
		t.Setenv("OS_KEYRING_USER", "my-user")

		svc, usr, err := getEnv()
		require.NoError(t, err)
		assert.Equal(t, "my-service", svc)
		assert.Equal(t, "my-user", usr)
	})

	t.Run("should return error if SERVICE_NAME is not set", func(t *testing.T) {
		t.Setenv("SERVICE_NAME", "")
		t.Setenv("OS_KEYRING_USER", "my-user")

		_, _, err := getEnv()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "env for service name is not set")
	})

	t.Run("should return error if OS_KEYRING_USER is not set", func(t *testing.T) {
		t.Setenv("SERVICE_NAME", "my-service")
		t.Setenv("OS_KEYRING_USER", "")

		_, _, err := getEnv()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "env for local keyring user is not set")
	})
}

func TestOsKeyring_Init(t *testing.T) {
	t.Run("should initialize a new key if not found", func(t *testing.T) {
		setupEnv(t)
		keyring.MockInit() // Use mock keyring

		kr := OsKeyring{}
		err := kr.Init()
		require.NoError(t, err)

		// Verify key was created in the mock store
		secret, err := keyring.Get(testService, testUser)
		require.NoError(t, err)
		assert.NotEmpty(t, secret)

		// Verify key is valid base64 and has correct decoded length
		decoded, err := base64.StdEncoding.DecodeString(secret)
		require.NoError(t, err)
		assert.Len(t, decoded, 32)
	})

	t.Run("should do nothing if key already exists", func(t *testing.T) {
		setupEnv(t)
		keyring.MockInit() // Use mock keyring

		existingSecret := "existing-secret"
		err := keyring.Set(testService, testUser, existingSecret)
		require.NoError(t, err)

		kr := OsKeyring{}
		err = kr.Init()
		require.NoError(t, err)

		// Verify key was not changed
		secret, err := keyring.Get(testService, testUser)
		require.NoError(t, err)
		assert.Equal(t, existingSecret, secret)
	})

	t.Run("should return error if envs are not set", func(t *testing.T) {
		keyring.MockInit()
		// No t.Setenv calls here to ensure they are empty
		t.Setenv("SERVICE_NAME", "")
		t.Setenv("OS_KEYRING_USER", "")
		kr := OsKeyring{}
		err := kr.Init()
		require.Error(t, err)
	})
}

func TestOsKeyring_GetKey(t *testing.T) {
	t.Run("should return key successfully", func(t *testing.T) {
		setupEnv(t)
		keyring.MockInit() // Use mock keyring

		// Create a valid key and set it
		keyBytes := make([]byte, keystore.KEY_SIZE)
		_, err := rand.Read(keyBytes)
		require.NoError(t, err)
		encodedKey := base64.StdEncoding.EncodeToString(keyBytes)

		err = keyring.Set(testService, testUser, encodedKey)
		require.NoError(t, err)

		kr := OsKeyring{}
		retrievedKey, err := kr.GetKey()
		require.NoError(t, err)
		assert.Equal(t, keyBytes, retrievedKey)
	})

	t.Run("should return error if key not found", func(t *testing.T) {
		setupEnv(t)
		keyring.MockInit() // Use mock keyring

		// Mock is empty by default, so no need to delete

		kr := OsKeyring{}
		_, err := kr.GetKey()
		require.Error(t, err)
		assert.ErrorIs(t, err, keyring.ErrNotFound)
	})

	t.Run("should return error for invalid base64", func(t *testing.T) {
		setupEnv(t)
		keyring.MockInit() // Use mock keyring

		err := keyring.Set(testService, testUser, "this is not base64")
		require.NoError(t, err)

		kr := OsKeyring{}
		_, err = kr.GetKey()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "illegal base64 data")
	})

	t.Run("should return error for unexpected key size", func(t *testing.T) {
		setupEnv(t)
		keyring.MockInit() // Use mock keyring

		shortKey := base64.StdEncoding.EncodeToString([]byte("short"))
		err := keyring.Set(testService, testUser, shortKey)
		require.NoError(t, err)

		kr := OsKeyring{}
		_, err = kr.GetKey()
		require.Error(t, err)
		assert.EqualError(t, err, "unexpected key size")
	})

	t.Run("should return error if envs are not set", func(t *testing.T) {
		keyring.MockInit()
		// No t.Setenv calls here to ensure they are empty
		t.Setenv("SERVICE_NAME", "")
		t.Setenv("OS_KEYRING_USER", "")
		kr := OsKeyring{}
		_, err := kr.GetKey()
		require.Error(t, err)
	})
}
