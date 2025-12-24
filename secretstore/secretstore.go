package secretstore

import (
	"context"
	"nidan-kai/binid"
)

type SecretStore interface {
	GetSecret(ctx context.Context, id binid.BinId) ([]byte, error)
	SetSecret(
		ctx context.Context,
		id binid.BinId,
		value []byte,
	) error
	Close() error
}
