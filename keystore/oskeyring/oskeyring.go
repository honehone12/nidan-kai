package oskeyring

import (
	"encoding/base64"
	"errors"
	"nidan-kai/keystore"
	"os"

	"github.com/zalando/go-keyring"
)

type OsKeyring struct{}

func getEnv() (string, string, error) {
	// don't inject other than env
	// to prevent exposing sensitive info
	// just write within module for testing

	svc := os.Getenv("SERVICE_NAME")
	if len(svc) == 0 {
		return "", "", errors.New("env for service name is not set")
	}

	usr := os.Getenv("LOCAL_KEYRING_USER")
	if len(usr) == 0 {
		return "", "", errors.New("env for local keyring user is not set")
	}

	return svc, usr, nil
}

func (o OsKeyring) Init() error {
	_, _, err := getEnv()
	return err
}

func (o OsKeyring) GetKey() ([]byte, error) {
	svc, usr, err := getEnv()
	if err != nil {
		return nil, err
	}

	s, err := keyring.Get(svc, usr)
	if err != nil {
		return nil, err
	}

	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}

	if len(b) != keystore.KEY_SIZE {
		return nil, errors.New("unexpected key size")
	}

	return b, nil
}
