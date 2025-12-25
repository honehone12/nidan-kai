package encryptedb

import (
	"context"
	"crypto/rand"
	"errors"
	"nidan-kai/binid"
	"nidan-kai/ent"
	"nidan-kai/ent/mfaqr"
	"nidan-kai/keystore"
	"nidan-kai/secret"

	"golang.org/x/crypto/chacha20poly1305"

	"entgo.io/ent/dialect/sql"
)

type EncrypteDB struct {
	ent      *ent.Client
	keystore keystore.Keystore
}

func NewEncrypteDB(
	ent *ent.Client,
	keystore keystore.Keystore,
) (*EncrypteDB, error) {
	if err := keystore.Init(); err != nil {
		return nil, err
	}
	return &EncrypteDB{ent, keystore}, nil
}

func (e *EncrypteDB) Close() error {
	return e.ent.Close()
}

func (e *EncrypteDB) GetSecret(ctx context.Context, id binid.BinId) ([]byte, error) {
	enc, err := e.query(ctx, id)
	if err != nil {
		return nil, err
	}

	return e.decrypt(enc)
}

func (e *EncrypteDB) decrypt(enc []byte) ([]byte, error) {
	key, err := e.keystore.GetKey()
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
	if len(dec) != secret.SECRET_LEN {
		return nil, errors.New("unexpected decrypted secret size")
	}

	return dec, nil
}

func (e *EncrypteDB) query(ctx context.Context, userId binid.BinId) ([]byte, error) {
	mfa, err := e.ent.MfaQr.Query().
		Select(
			mfaqr.FieldSecret,
		).
		Where(
			mfaqr.UserID(userId),
			mfaqr.DeletedAtIsNil(),
		).
		Order(
			sql.OrderByField(mfaqr.FieldCreatedAt, sql.OrderDesc()).ToFunc(),
		).
		Limit(1).
		First(ctx)
	if err != nil {
		// we can return NotFound as err
		// because id should be queried by email
		// and NotFound should be handled there
		return nil, err
	}

	return mfa.Secret, nil
}

func (e *EncrypteDB) SetSecret(
	ctx context.Context,
	id binid.BinId,
	value []byte,
) error {
	enc, err := e.encrypt(value)
	if err != nil {
		return err
	}

	return e.insert(ctx, id, enc)
}

func (e *EncrypteDB) encrypt(value []byte) ([]byte, error) {
	key, err := e.keystore.GetKey()
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

func (e *EncrypteDB) insert(
	ctx context.Context,
	userId binid.BinId,
	value []byte,
) error {
	id, err := binid.NewSequential()
	if err != nil {
		return err
	}

	return e.ent.MfaQr.Create().
		SetID(id).
		SetSecret(value).
		SetUserID(userId).
		Exec(ctx)
}
