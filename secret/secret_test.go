package secret

import (
	"bytes"
	"nidan-kai/keystore/envkey"
	"os"
	"testing"
)

var testKEY = "TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT="
var testBytes = []byte{0x4d, 0x34, 0xd3, 0x4d, 0x34, 0xd3, 0x4d, 0x34, 0xd3, 0x4d, 0x34, 0xd3, 0x4d, 0x34, 0xd3, 0x4d, 0x34, 0xd3, 0x4d, 0x34, 0xd3, 0x4d, 0x34, 0xd3, 0x4d, 0x34, 0xd3, 0x4d, 0x34, 0xd3, 0x4d, 0x34}
var envKey = "ENV_SECRET_KEY"

func Test_GenerateSecret(t *testing.T) {
	e := envkey.EnvKey{}

	b, err := GenerateEncryptedSecret(e)
	if err == nil {
		t.Fatalf("env is not set but got %v\n", b)
	}

	t.Setenv(envKey, testKEY)

	secret1, err := GenerateEncryptedSecret(envkey.EnvKey{})
	if err != nil {
		t.Fatal(err)
	}

	secret2, err := GenerateEncryptedSecret(envkey.EnvKey{})
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(secret1, secret2) {
		t.Fatal("secret is not random")
	}
}

func Test_Decrypt(t *testing.T) {
	e := envkey.EnvKey{}

	if err := os.Setenv(envKey, testKEY); err != nil {
		t.Fatal(err)
	}

	original, err := GenerateEncryptedSecret(e)
	if err != nil {
		t.Fatal(err)
	}

	dec, err := Decrypt(original, e)
	if err != nil {
		t.Fatal(err)
	}

	if len(dec) != SECRET_LEN {
		t.Fatal("wrong decrypted")
	}

	if err := os.Unsetenv(envKey); err != nil {
		t.Fatal(err)
	}

	dec, err = Decrypt(original, e)
	if err == nil {
		t.Fatal("env is not set but err is nil")
	}
}

func Test_DecryptVars(t *testing.T) {
	e := envkey.EnvKey{}
	t.Setenv(envKey, testKEY)

	fail := []byte{7, 7, 7}

	dec, err := Decrypt(fail, e)
	if err == nil {
		t.Fatalf("should fail, but returns %v\n", dec)
	}

	failEnc, err := encrypt(fail, e)
	if err != nil {
		t.Fatal(err)
	}

	dec, err = Decrypt(failEnc, e)
	if err == nil {
		t.Fatalf("should fail, but returns %v\n", dec)
	}
}
