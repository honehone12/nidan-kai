package secret

import "crypto/rand"

const SECRET_LEN = 32

func GenerateSecret() ([]byte, error) {
	sec := make([]byte, SECRET_LEN)
	_, err := rand.Read(sec)
	if err != nil {
		return nil, err
	}

	return sec, nil
}
