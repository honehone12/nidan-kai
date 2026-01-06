package envkey

import (
	"bytes"
	"nidan-kai/keystore"
	"testing"
)

var _ keystore.Keystore = EnvKey{}

var testKEY = "TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT="
var testBytes = []byte{0x4d, 0x34, 0xd3, 0x4d, 0x34, 0xd3, 0x4d, 0x34, 0xd3, 0x4d, 0x34, 0xd3, 0x4d, 0x34, 0xd3, 0x4d, 0x34, 0xd3, 0x4d, 0x34, 0xd3, 0x4d, 0x34, 0xd3, 0x4d, 0x34, 0xd3, 0x4d, 0x34, 0xd3, 0x4d, 0x34}
var envKey = "ENV_SECRET_KEY"

func Test_getEnv(t *testing.T) {
	s, err := getEnv()
	if err == nil {
		t.Fatalf("env is not set, but got %s\n", s)
	}

	t.Setenv(envKey, testKEY)

	s, err = getEnv()
	if err != nil {
		t.Fatal(err)
	}

	if s != testKEY {
		t.Fatal("wrong env")
	}

}

func Test_GetKey(t *testing.T) {
	e := EnvKey{}
	t.Setenv(envKey, testKEY)

	b, err := e.GetKey()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(b, testBytes) {
		t.Fatal("wrong bytes")
	}
}
