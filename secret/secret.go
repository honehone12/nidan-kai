package secret

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"nidan-kai/keystore"

	"golang.org/x/crypto/chacha20poly1305"
)

const SECRET_LEN = 20 // (20 / 5 * 8 = 32)

func GenerateEncryptedSecret(keystore keystore.Keystore) ([]byte, error) {
	sec := make([]byte, SECRET_LEN)
	_, err := rand.Read(sec)
	if err != nil {
		return nil, err
	}

	return Encrypt(sec, keystore)
}

func SecretEncoder() *base32.Encoding {
	return base32.StdEncoding.WithPadding(base32.NoPadding)
}

func Encrypt(value []byte, keystore keystore.Keystore) ([]byte, error) {
	key, err := keystore.GetKey()
	if err != nil {
		return nil, err
	}

	chacha, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonceSize := chacha.NonceSize()
	cipher := make([]byte, nonceSize, nonceSize+len(value)+chacha.Overhead())
	_, err = rand.Read(cipher)
	if err != nil {
		return nil, err
	}

	enc := chacha.Seal(cipher, cipher[:nonceSize], value, nil)
	return enc, nil
}

func Decrypt(enc []byte, keystore keystore.Keystore) ([]byte, error) {
	key, err := keystore.GetKey()
	if err != nil {
		return nil, err
	}

	chacha, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonceSize := chacha.NonceSize()
	if len(enc) <= nonceSize {
		return nil, errors.New("unexpected encryptedd secret size")
	}

	dec, err := chacha.Open(nil, enc[:nonceSize], enc[nonceSize:], nil)
	if err != nil {
		return nil, err
	}
	if len(dec) != SECRET_LEN {
		return nil, errors.New("unexpected decrypted secret size")
	}

	return dec, nil
}
