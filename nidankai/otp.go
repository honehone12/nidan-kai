package nidankai

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"math"
)

const QR_SIZE = 256
const QR_MFA_DIGITS = 6
const QR_MFA_ARGORITHM = "SHA1"
const QR_MFA_PERIOD = 30

var __QrMfaPowered = uint32(math.Pow10(QR_MFA_DIGITS))

func Hotp(secret []byte, nonce [8]byte) (int32, error) {
	hmac := hmac.New(sha1.New, secret)
	if n, err := hmac.Write(nonce[:]); err != nil || n != 8 {
		return 0, errors.New("failed to write noce to hasher")
	}

	h := hmac.Sum(nil)                // sha1.Size=20
	offset := int(h[len(h)-1] & 0x0f) // max=15
	n := binary.BigEndian.Uint32(h[offset : offset+4])
	n &= 0x7fffffff                   // 0b01111111......
	code := int32(n % __QrMfaPowered) // max=999999
	return code, nil
}

func Totp(secret []byte, t, p int64) (int32, error) {
	counter := uint64(t / p)
	buf := [8]byte{}
	binary.BigEndian.PutUint64(buf[:], counter)
	return Hotp(secret, buf)
}
