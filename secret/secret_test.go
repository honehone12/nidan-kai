package secret

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSecret(t *testing.T) {
	t.Run("should generate a secret of correct length", func(t *testing.T) {
		secret, err := GenerateSecret()
		require.NoError(t, err)
		assert.Len(t, secret, SECRET_LEN)
	})

	t.Run("should generate different secrets on multiple calls", func(t *testing.T) {
		secret1, err := GenerateSecret()
		require.NoError(t, err)

		secret2, err := GenerateSecret()
		require.NoError(t, err)

		assert.NotEqual(t, secret1, secret2, "secrets should be different")
	})
}

func TestSecretEncoder(t *testing.T) {
	t.Run("should return a base32 encoder with no padding", func(t *testing.T) {
		encoder := SecretEncoder()
		assert.NotNil(t, encoder)

		// Test with a known value to ensure no padding
		data := []byte{0x10, 0x20, 0x30, 0x40, 0x50} // 5 bytes = 8 base32 chars with no padding
		encoded := encoder.EncodeToString(data)
		assert.Equal(t, "CAQDAQCQ", encoded) // (1020304050 base16 to base32 conversion)

		decoded, err := encoder.DecodeString(encoded)
		require.NoError(t, err)
		assert.True(t, bytes.Equal(data, decoded))

		// Test with data that would normally have padding if not for NoPadding
		data2 := []byte{0x01, 0x23} // 2 bytes
		encoded2 := encoder.EncodeToString(data2)
		assert.Equal(t, "AERQ", encoded2) // Expected: AEBA==== if padded, but AEBAA if NoPadding

		decoded2, err := encoder.DecodeString(encoded2)
		require.NoError(t, err)
		assert.True(t, bytes.Equal(data2, decoded2))
	})
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
