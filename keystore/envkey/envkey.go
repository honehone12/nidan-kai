package envkey

import (
	"encoding/base64"
	"errors"
	"nidan-kai/keystore"
	"os"
	"unicode/utf8"
)

type EnvKey struct{}

func getEnv() (string, error) {
	// don't inject other than env
	// to prevent exposing sensitive info
	// just write within module for testing

	key := os.Getenv("ENV_SECRET_KEY")
	if len(key) == 0 {
		return "", errors.New("env for env secret key is not set")
	}

	return key, nil
}

func (e EnvKey) Init() error {
	_, err := getEnv()
	if err != nil {
		return err
	}

	return nil
}

func (e EnvKey) GetKey() ([]byte, error) {
	s, err := getEnv()
	if err != nil {
		return nil, err
	}

	// this is actually bypassed when it's utf-16 etc
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
