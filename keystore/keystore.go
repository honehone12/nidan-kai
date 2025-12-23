package keystore

const KEY_SIZE = 32

type Keystore interface {
	Init() error
	GetKey() ([]byte, error)
}
