package secretstore

import (
	"context"
	"nidan-kai/id"
)

type SecretStore interface {
	GetSecret(ctx context.Context, id id.Id) ([]byte, error)
	SetSecret(
		ctx context.Context,
		id id.Id,
		value []byte,
	) error
}
