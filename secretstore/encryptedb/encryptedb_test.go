package encryptedb

import "nidan-kai/secretstore"

var _ secretstore.SecretStore = &EncrypteDB{}
