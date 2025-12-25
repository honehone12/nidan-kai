package encryptedb

import (
	"context"
	"crypto/rand"
	"nidan-kai/binid"
	"nidan-kai/ent"
	"nidan-kai/ent/enttest"
	"nidan-kai/secret"
	"nidan-kai/secretstore"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

// This ensures EncrypteDB implements the secretstore.SecretStore interface.
var _ secretstore.SecretStore = &EncrypteDB{}

// mockKeystore is a mock implementation of the keystore.Keystore interface for testing.
type mockKeystore struct {
	key     []byte
	initErr error
	getErr  error
}

func (m *mockKeystore) Init() error {
	return m.initErr
}

func (m *mockKeystore) GetKey() ([]byte, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.key, nil
}

// newMockKeystore creates a mock keystore with a valid 32-byte key.
func newMockKeystore() *mockKeystore {
	key := make([]byte, chacha20poly1305.KeySize)
	_, _ = rand.Read(key)
	return &mockKeystore{key: key}
}

// setupTest initializes an in-memory SQLite DB, a mock keystore, and the EncrypteDB service.
func setupTest(t *testing.T) (*ent.Client, *EncrypteDB, *mockKeystore) {
	t.Helper()

	// Create an in-memory SQLite client using Open for a real connection.
	opts := []enttest.Option{
		enttest.WithOptions(ent.Log(t.Log)),
	}
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1", opts...)
	t.Cleanup(func() { client.Close() })

	mockKS := newMockKeystore()

	// We pass client.MfaQr to NewEncrypteDB, but use the mock for keystore
	// so we don't need to call the constructor which calls Init().
	encryptedDB := &EncrypteDB{
		mfaQrClient: client.MfaQr,
		keystore:    mockKS,
	}

	return client, encryptedDB, mockKS
}

func TestNewEncrypteDB(t *testing.T) {
	t.Run("should succeed when keystore init succeeds", func(t *testing.T) {
		client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
		defer client.Close()

		mockKS := newMockKeystore()
		mockKS.initErr = nil

		db, err := NewEncrypteDB(client.MfaQr, mockKS)
		require.NoError(t, err)
		assert.NotNil(t, db)
	})

	t.Run("should fail when keystore init fails", func(t *testing.T) {
		client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
		defer client.Close()

		mockKS := newMockKeystore()
		mockKS.initErr = assert.AnError

		db, err := NewEncrypteDB(client.MfaQr, mockKS)
		require.Error(t, err)
		assert.ErrorIs(t, err, assert.AnError)
		assert.Nil(t, db)
	})
}

func TestEncrypteDB_SetAndGetSecret_Integration(t *testing.T) {
	ctx := context.Background()
	client, e, _ := setupTest(t)

	userID, err := binid.NewRandom()
	require.NoError(t, err)

	// Create a user to satisfy the foreign key constraint
	err = client.User.Create().
		SetID(userID).
		SetName("test-user").
		SetEmail("test@example.com").
		Exec(ctx)
	require.NoError(t, err)

	originalSecret, err := secret.GenerateSecret()
	require.NoError(t, err)

	// Set the secret
	err = e.SetSecret(ctx, userID, originalSecret)
	require.NoError(t, err)

	// Get the secret
	retrievedSecret, err := e.GetSecret(ctx, userID)
	require.NoError(t, err)

	// Verify they are the same
	assert.Equal(t, originalSecret, retrievedSecret)
}

func TestEncrypteDB_encrypt_decrypt(t *testing.T) {
	_, e, mockKS := setupTest(t)

	originalSecret, err := secret.GenerateSecret()
	require.NoError(t, err)

	t.Run("should encrypt and decrypt successfully", func(t *testing.T) {
		encrypted, err := e.encrypt(originalSecret)
		require.NoError(t, err)
		assert.NotEqual(t, originalSecret, encrypted)

		decrypted, err := e.decrypt(encrypted)
		require.NoError(t, err)
		assert.Equal(t, originalSecret, decrypted)
	})

	t.Run("should fail encrypt on keystore error", func(t *testing.T) {
		mockKS.getErr = assert.AnError
		_, err := e.encrypt(originalSecret)
		require.ErrorIs(t, err, assert.AnError)
		mockKS.getErr = nil // reset
	})

	t.Run("should fail decrypt on keystore error", func(t *testing.T) {
		encrypted, _ := e.encrypt(originalSecret)
		mockKS.getErr = assert.AnError
		_, err := e.decrypt(encrypted)
		require.ErrorIs(t, err, assert.AnError)
		mockKS.getErr = nil // reset
	})

	t.Run("should fail decrypt on short ciphertext", func(t *testing.T) {
		shortCipher := []byte{1, 2, 3}
		_, err := e.decrypt(shortCipher)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected encryptedd secret size")
	})

	t.Run("should fail decrypt on invalid decrypted size", func(t *testing.T) {
		// Encrypt a value that doesn't have the expected SECRET_LEN
		invalidSecret := []byte("this is not the right size")
		encrypted, err := e.encrypt(invalidSecret)
		require.NoError(t, err)

		_, err = e.decrypt(encrypted)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected decrypted secret size")
	})
}

func TestEncrypteDB_GetSecret_Errors(t *testing.T) {
	ctx := context.Background()
	client, e, mockKS := setupTest(t)

	userID, _ := binid.NewRandom()
	originalSecret, _ := secret.GenerateSecret()

	// Create a user to satisfy the foreign key constraint
	err := client.User.Create().
		SetID(userID).
		SetName("test-user-errors").
		SetEmail("test-errors@example.com").
		Exec(ctx)
	require.NoError(t, err)

	// Set a secret to test against
	err = e.SetSecret(ctx, userID, originalSecret)
	require.NoError(t, err)

	t.Run("should return NotFound error for non-existent user", func(t *testing.T) {
		nonExistentID, _ := binid.NewRandom()
		_, err := e.GetSecret(ctx, nonExistentID)
		require.Error(t, err)
		assert.True(t, ent.IsNotFound(err), "expected a NotFound error")
	})

	t.Run("should return error on keystore failure", func(t *testing.T) {
		mockKS.getErr = assert.AnError
		_, err := e.GetSecret(ctx, userID)
		require.ErrorIs(t, err, assert.AnError)
		mockKS.getErr = nil // reset
	})
}

func TestEncrypteDB_SetSecret_Errors(t *testing.T) {
	ctx := context.Background()
	_, e, mockKS := setupTest(t)

	userID, _ := binid.NewRandom()
	originalSecret, _ := secret.GenerateSecret()

	t.Run("should return error on keystore failure", func(t *testing.T) {
		mockKS.getErr = assert.AnError
		err := e.SetSecret(ctx, userID, originalSecret)
		require.ErrorIs(t, err, assert.AnError)
		mockKS.getErr = nil // reset
	})

	t.Run("should return error on db failure", func(t *testing.T) {
		// Simulate a DB failure by closing the client immediately
		client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
		client.Close()

		dbWithBadClient := &EncrypteDB{
			mfaQrClient: client.MfaQr,
			keystore:    mockKS,
		}

		err := dbWithBadClient.SetSecret(ctx, userID, originalSecret)
		require.Error(t, err)
	})
}