package nidankai

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"nidan-kai/secret"
	"strconv"
	"time"

	"github.com/skip2/go-qrcode"
)

func SetUp(appName, email string, secretKey []byte) (string, error) {
	encSec := secret.SecretEncoder().EncodeToString(secretKey)
	path := url.PathEscape(fmt.Sprintf("%s:%s", appName, email))
	query := url.Values{}
	query.Set("secret", encSec)
	query.Set("issuer", appName)
	query.Set("algorithm", QR_MFA_ARGORITHM)
	query.Set("digits", strconv.Itoa(QR_MFA_DIGITS))
	query.Set("period", strconv.Itoa(QR_MFA_PERIOD))
	url := fmt.Sprintf("otpauth://totp/%s?%s", path, query.Encode())

	qr, err := qrcode.Encode(url, qrcode.Medium, QR_SIZE)
	if err != nil {
		return "", err
	}

	encQr := base64.StdEncoding.EncodeToString(qr)
	return "data:image/png;base64," + encQr, nil
}

func Verify(code int, secretKey []byte) (bool, error) {
	if code >= int(__QrMfaPowered) {
		return false, errors.New("invalid code")
	}

	now := time.Now().Unix()
	otp, err := Totp(secretKey, now, QR_MFA_PERIOD)
	if err != nil {
		return false, err
	}

	if subtle.ConstantTimeEq(otp, int32(code)) != 1 {
		return false, nil
	}

	return true, nil
}
