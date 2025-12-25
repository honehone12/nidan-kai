package nidankai

import (
	"context"
	"encoding/binary"
	"fmt"
	"nidan-kai/binid"
	"nidan-kai/secret"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSecretStore is a mock implementation of the secretstore.SecretStore interface.
type mockSecretStore struct {
	store map[binid.BinId][]byte
	err   error
}

func newMockSecretStore() *mockSecretStore {
	return &mockSecretStore{
		store: make(map[binid.BinId][]byte),
	}
}

func (m *mockSecretStore) GetSecret(ctx context.Context, id binid.BinId) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	sec, ok := m.store[id]
	if !ok {
		return nil, fmt.Errorf("secret not found for user %s", id)
	}
	return sec, nil
}

func (m *mockSecretStore) SetSecret(ctx context.Context, id binid.BinId, value []byte) error {
	if m.err != nil {
		return m.err
	}
	m.store[id] = value
	return nil
}

func TestNewNidankai(t *testing.T) {
	mockStore := newMockSecretStore()
	n, err := NewNidankai(mockStore)
	require.NoError(t, err)
	assert.NotNil(t, n)
	assert.Equal(t, mockStore, n.secretStore)
}

func Test_hotp(t *testing.T) {
	// Test cases from RFC 4226 Appendix D
	secret := []byte("12345678901234567890")
	testCases := []struct {
		count    uint64
		expected int32
	}{
		{0, 755224},
		{1, 287082},
		{2, 359152},
		{3, 969429},
		{4, 338314},
		{5, 254676},
		{6, 287922},
		{7, 162583},
		{8, 399871},
		{9, 520489},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("count_%d", tc.count), func(t *testing.T) {
			nonce := [8]byte{}
			binary.BigEndian.PutUint64(nonce[:], tc.count)
			code, err := hotp(secret, nonce)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, code)
		})
	}
}

func Test_totp(t *testing.T) {
	// Test cases from RFC 6238 Appendix B, adapted for 6 digits
	secret := []byte("12345678901234567890")
	testCases := []struct {
		time     int64
		expected int32
	}{
		{59, 287082},
		{1111111109, 81804},
		{1111111111, 50471},
		{1234567890, 5924},
		{2000000000, 279037},
		{20000000000, 353130},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("time_%d", tc.time), func(t *testing.T) {
			code, err := totp(secret, tc.time, QR_MFA_PERIOD)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, code)
		})
	}
}

func TestNidanKai_SetUp(t *testing.T) {
	ctx := context.Background()
	mockStore := newMockSecretStore()
	n, _ := NewNidankai(mockStore)

	userID, _ := binid.NewRandom()
	params := SetUpParams{
		Issuer: "TestApp",
		UserId: userID,
		Email:  "test@example.com",
	}

	t.Run("should set up successfully", func(t *testing.T) {
		qrString, err := n.SetUp(ctx, params)
		require.NoError(t, err)

		// Check QR string format
		assert.True(t, strings.HasPrefix(qrString, "data:image/png;base64,"))
		assert.NotEmpty(t, strings.TrimPrefix(qrString, "data:image/png;base64,"))

		// Check if secret was stored
		storedSecret, err := mockStore.GetSecret(ctx, userID)
		require.NoError(t, err)
		assert.NotNil(t, storedSecret)
		assert.Len(t, storedSecret, 20) // secret.SECRET_LEN
	})

	t.Run("should fail if secret store fails", func(t *testing.T) {
		mockStore.err = assert.AnError
		_, err := n.SetUp(ctx, params)
		require.Error(t, err)
		assert.ErrorIs(t, err, assert.AnError)
		mockStore.err = nil // reset
	})
}

func TestNidanKai_Verify(t *testing.T) {
	ctx := context.Background()
	mockStore := newMockSecretStore()
	n, _ := NewNidankai(mockStore)

	userID, _ := binid.NewRandom()
	secret, _ := secret.GenerateSecret()
	mockStore.SetSecret(ctx, userID, secret)

	t.Run("should verify correct code successfully", func(t *testing.T) {
		now := time.Now().Unix()
		correctCode, err := totp(secret, now, QR_MFA_PERIOD)
		require.NoError(t, err)

		params := VerifyParams{
			UserId: userID,
			Code:   int(correctCode),
		}

		ok, err := n.Verify(ctx, params)
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("should fail for incorrect code", func(t *testing.T) {
		now := time.Now().Unix()
		correctCode, err := totp(secret, now, QR_MFA_PERIOD)
		require.NoError(t, err)

		// Get an incorrect code
		incorrectCode := (correctCode + 1) % 1000000

		params := VerifyParams{
			UserId: userID,
			Code:   int(incorrectCode),
		}

		ok, err := n.Verify(ctx, params)
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("should return error for invalid code format", func(t *testing.T) {
		params := VerifyParams{
			UserId: userID,
			Code:   1000000, // Code is too large
		}
		ok, err := n.Verify(ctx, params)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid code")
		assert.False(t, ok)
	})

	t.Run("should return error if secret not found", func(t *testing.T) {
		nonExistentID, _ := binid.NewRandom()
		params := VerifyParams{
			UserId: nonExistentID,
			Code:   123456,
		}
		ok, err := n.Verify(ctx, params)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secret not found")
		assert.False(t, ok)
	})
}
