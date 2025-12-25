package oskeyring

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"nidan-kai/keystore"
	"os"
	"unicode/utf8"

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

	usr := os.Getenv("OS_KEYRING_USER")
	if len(usr) == 0 {
		return "", "", errors.New("env for local keyring user is not set")
	}

	return svc, usr, nil
}

func (o OsKeyring) Init() error {
	svc, usr, err := getEnv()
	if err != nil {
		return err
	}

	_, err = keyring.Get(svc, usr)
	if errors.Is(err, keyring.ErrNotFound) {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}

		p := base64.StdEncoding.EncodeToString(b)
		if err := keyring.Set(svc, usr, p); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	return nil
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

	// this is actually bypassed whem it's utf-16 etc
	if !utf8.ValidString(s) {
		return nil, errors.New("this is not a utf-8 string")
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
