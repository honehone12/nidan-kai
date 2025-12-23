package keystore

type Keystore interface {
	Get() (string, error)
}
