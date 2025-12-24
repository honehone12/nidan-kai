package secret

import (
	"crypto/rand"
	"encoding/base32"
)

const SECRET_LEN = 20 // (20 / 5 * 8 = 32)

func GenerateSecret() ([]byte, error) {
	sec := make([]byte, SECRET_LEN)
	_, err := rand.Read(sec)
	if err != nil {
		return nil, err
	}

	return sec, nil
}

func SecretEncoder() *base32.Encoding {
	return base32.StdEncoding.WithPadding(base32.NoPadding)
}
