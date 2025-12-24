package nidankai

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"nidan-kai/binid"
	"nidan-kai/secret"
	"nidan-kai/secretstore"

	"github.com/skip2/go-qrcode"
)

const QR_SIZE = 256
const QR_MFA_DIGITS = 6
const QR_MFA_ARGORITHM = "SHA-1"
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
	query := url.QueryEscape(fmt.Sprintf(
		"secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
		encSec,
		p.Issuer,
		QR_MFA_ARGORITHM,
		QR_MFA_DIGITS,
		QR_MFA_PERIOD,
	))
	url := fmt.Sprintf("otpauth://totp/%s?%s", path, query)
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
