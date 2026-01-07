package nidankai

import (
	"encoding/binary"
	"fmt"
	"nidan-kai/keystore/envkey"
	"nidan-kai/secret"
	"strings"
	"testing"
	"time"
)

var testKEY = "TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT="
var envKey = "ENV_SECRET_KEY"

func Test_Hotp(t *testing.T) {
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
			code, err := Hotp(secret, nonce)
			if err != nil {
				t.Fatal(err)
			}
			if tc.expected != code {
				t.Fatal("seems generating invalid hotp code")
			}
		})
	}
}

func Test_Totp(t *testing.T) {
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
			code, err := Totp(secret, tc.time, QR_MFA_PERIOD)
			if err != nil {
				t.Fatal(err)
			}
			if tc.expected != code {
				t.Fatal("seems generating invlid totp code")
			}
		})
	}
}

func TestNidanKai_SetUp(t *testing.T) {
	t.Setenv(envKey, testKEY)
	envStore := envkey.EnvKey{}
	secret, err := secret.GenerateEncryptedSecret(envStore)
	if err != nil {
		t.Fatal(err)
	}
	issuer := "TestApp"
	email := "test@example.com"

	qrString, err := SetUp(issuer, email, secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(qrString) == 0 {
		t.Fatal("empty qr")
	}
	if !strings.HasPrefix(qrString, "data:image/png;base64,") {
		t.Fatal("invalid qr format")
	}
}

func TestNidanKai_Verify(t *testing.T) {
	t.Setenv(envKey, testKEY)
	envStore := envkey.EnvKey{}
	secret, err := secret.GenerateEncryptedSecret(envStore)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("should success", func(t *testing.T) {
		now := time.Now().Unix()
		correctCode, err := Totp(secret, now, QR_MFA_PERIOD)
		if err != nil {
			t.Fatal(err)
		}

		ok, err := Verify(int(correctCode), secret)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatal("should success but returned false")
		}
	})

	t.Run("should fail", func(t *testing.T) {
		now := time.Now().Unix()
		correctCode, err := Totp(secret, now, QR_MFA_PERIOD)
		if err != nil {
			t.Fatal(err)
		}

		// Get an incorrect code
		incorrectCode := (correctCode + 1) % 1000000

		ok, err := Verify(int(incorrectCode), secret)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Fatal("should fail but returned true")
		}
	})

	t.Run("should return error for invalid code format", func(t *testing.T) {
		ok, err := Verify(1000000, secret)
		if err == nil || ok {
			t.Fatal("should fail but retured ok")
		}
	})
}
