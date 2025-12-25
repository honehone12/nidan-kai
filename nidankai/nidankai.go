package nidankai

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/url"
	"nidan-kai/binid"
	"nidan-kai/secret"
	"nidan-kai/secretstore"
	"strconv"
	"time"

	"github.com/skip2/go-qrcode"
)

const QR_SIZE = 256
const QR_MFA_DIGITS = 6
const QR_MFA_ARGORITHM = "SHA1"
const QR_MFA_PERIOD = 30

var __QrMfaPowered = uint32(math.Pow10(QR_MFA_DIGITS))

type NidanKai struct {
	secretStore secretstore.SecretStore
}

type SetUpParams struct {
	Issuer string
	UserId binid.BinId
	Email  string
}

type VerifyParams struct {
	UserId binid.BinId
	Code   int
}

func NewNidankai(secretStore secretstore.SecretStore) (*NidanKai, error) {
	return &NidanKai{secretStore}, nil
}

func (n *NidanKai) SetUp(ctx context.Context, p SetUpParams) (string, error) {
	sec, err := secret.GenerateSecret()
	if err != nil {
		return "", err
	}

	encSec := secret.SecretEncoder().EncodeToString(sec)
	path := url.PathEscape(fmt.Sprintf("%s:%s", p.Issuer, p.Email))
	query := url.Values{}
	query.Set("secret", encSec)
	query.Set("issuer", p.Issuer)
	query.Set("algorithm", QR_MFA_ARGORITHM)
	query.Set("digits", strconv.Itoa(QR_MFA_DIGITS))
	query.Set("period", strconv.Itoa(QR_MFA_PERIOD))
	url := fmt.Sprintf("otpauth://totp/%s?%s", path, query.Encode())

	qr, err := qrcode.Encode(url, qrcode.Medium, QR_SIZE)
	if err != nil {
		return "", err
	}

	if err := n.secretStore.SetSecret(ctx, p.UserId, sec); err != nil {
		return "", err
	}

	encQr := base64.StdEncoding.EncodeToString(qr)
	return "data:image/png;base64," + encQr, nil
}

func hotp(secret []byte, nonce [8]byte) (int32, error) {
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

func totp(secret []byte, t, p int64) (int32, error) {
	counter := uint64(t / p)
	buf := [8]byte{}
	binary.BigEndian.PutUint64(buf[:], counter)
	return hotp(secret, buf)
}

func (n *NidanKai) Verify(ctx context.Context, p VerifyParams) (bool, error) {
	if p.Code >= int(__QrMfaPowered) {
		return false, errors.New("invalid code")
	}

	sec, err := n.secretStore.GetSecret(ctx, p.UserId)
	if err != nil {
		return false, err
	}

	now := time.Now().Unix()
	code, err := totp(sec, now, QR_MFA_PERIOD)
	if err != nil {
		return false, err
	}

	if subtle.ConstantTimeEq(code, int32(p.Code)) != 1 {
		return false, nil
	}

	return true, nil
}
