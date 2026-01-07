package oskeyring

import (
	"bytes"
	"nidan-kai/keystore"
	"os"
	"testing"

	"github.com/zalando/go-keyring"
)

// This ensures OsKeyring implements the keystore.Keystore interface.
var _ keystore.Keystore = OsKeyring{}

var (
	serviceKey  = "SERVICE_NAME"
	userKey     = "OS_KEYRING_USER"
	testService = "nidan-kai-test-service"
	testUser    = "nidan-kai-test-user"
)

func setupEnv(t *testing.T) {
	t.Setenv(serviceKey, testService)
	t.Setenv(userKey, testUser)
}

func Test_getEnv(t *testing.T) {
	s, u, err := getEnv()
	if err == nil {
		t.Fatalf("env is not set but returns %v %v\n", s, u)
	}

	t.Run("no env", func(t *testing.T) {
		t.Setenv(serviceKey, testService)
		s, u, err := getEnv()
		if err == nil {
			t.Fatalf("env is not set but returns %v %v\n", s, u)
		}
	})

	t.Run("service env only", func(t *testing.T) {
		t.Setenv(serviceKey, testService)
		s, u, err := getEnv()
		if err == nil {
			t.Fatalf("env is not set but returns %v %v\n", s, u)
		}
	})

	t.Run("user env only", func(t *testing.T) {
		t.Setenv(userKey, testUser)
		s, u, err := getEnv()
		if err == nil {
			t.Fatalf("env is not set but returns %v %v\n", s, u)
		}
	})

	t.Run("should ok", func(t *testing.T) {
		setupEnv(t)
		s, u, err := getEnv()
		if err != nil {
			t.Fatal(err)
		}
		if s != testService {
			t.Fatal("wrong service name")
		}
		if u != testUser {
			t.Fatal("wrong user name")
		}
	})
}

func TestOsKeyring_Init_to_Get(t *testing.T) {
	setupEnv(t)
	keyring.MockInit() // Use mock keyring

	kr := OsKeyring{}
	err := kr.Init()
	if err != nil {
		t.Fatal(err)
	}

	// Verify key was created in the mock store
	secret, err := kr.GetKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) == 0 {
		t.Fatal("returned empty secret")
	}

	secret1, err := kr.GetKey()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(secret, secret1) {
		t.Fatal("returned different secrets")
	}
}

func Test_Fail(t *testing.T) {
	t.Run("should fail init", func(t *testing.T) {
		keyring.MockInit()
		kr := OsKeyring{}
		err := kr.Init()
		if err == nil {
			t.Fatal("should fail without env")
		}
	})

	t.Run("should fail get", func(t *testing.T) {
		keyring.MockInit()
		if err := os.Setenv(serviceKey, testService); err != nil {
			t.Fatal(err)
		}
		if err := os.Setenv(userKey, testUser); err != nil {
			t.Fatal(err)
		}

		kr := OsKeyring{}
		if err := kr.Init(); err != nil {
			t.Fatal(err)
		}

		if err := os.Unsetenv(serviceKey); err != nil {
			t.Fatal(err)
		}
		if err := os.Unsetenv(userKey); err != nil {
			t.Fatal(err)
		}

		b, err := kr.GetKey()
		if err == nil {
			t.Fatalf("should fail without env but returned %v\n", b)
		}
	})
}
