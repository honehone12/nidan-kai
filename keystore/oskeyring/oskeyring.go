package oskeyring

import (
	"errors"
	"os"

	"github.com/zalando/go-keyring"
)

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

func Set(value string) error {
	// don't use this func for testing other modules
	// i mean don't create new password for testing
	// just load existing password instead

	svc, usr, err := getEnv()
	if err != nil {
		return err
	}

	return keyring.Set(svc, usr, value)
}

func Get() (string, error) {
	svc, usr, err := getEnv()
	if err != nil {
		return "", err
	}

	return keyring.Get(svc, usr)
}
