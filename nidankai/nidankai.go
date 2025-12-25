package nidankai

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"nidan-kai/binid"
	"nidan-kai/secret"
	"nidan-kai/secretstore"
	"strconv"

	"github.com/skip2/go-qrcode"
)

const QR_SIZE = 256
const QR_MFA_DIGITS = 6
const QR_MFA_ARGORITHM = "SHA1"
const QR_MFA_PERIOD = 30

type NidanKai struct {
	secretStore secretstore.SecretStore
}

type SetUpParams struct {
	Issuer    string
	UserId    binid.BinId
	UserEmail string
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
	path := url.PathEscape(fmt.Sprintf("%s:%s", p.Issuer, p.UserEmail))
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

func (n *NidanKai) Close() error {
	return n.secretStore.Close()
}
