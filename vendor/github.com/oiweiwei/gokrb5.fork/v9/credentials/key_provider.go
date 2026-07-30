package credentials

import (
	"fmt"

	"github.com/oiweiwei/gokrb5.fork/v9/keytab"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
)

// KeyProvider is an interface for providing encryption keys.
type KeyProvider interface {
	// GetEncryptionKey returns the encryption key for the principal, realm, key version
	// number and encryption type.
	GetEncryptionKey(types.PrincipalName, string, int, int32) (types.EncryptionKey, int, error)
}

// Keyset is a slice of encryption keys.
type Keyset []types.EncryptionKey

// GetEncryptionKey returns the encryption key for the principal, realm, key version
// number and encryption type.
func (k Keyset) GetEncryptionKey(_ types.PrincipalName, _ string, _ int, etype int32) (types.EncryptionKey, int, error) {
	for _, key := range k {
		if etype == 0 || etype == key.KeyType {
			return key, 0, nil
		}
	}
	return types.EncryptionKey{}, 0, fmt.Errorf("matching key not found in keyset. Looking for etype: %v", etype)
}

var (
	_ KeyProvider = (Keyset)(nil)
	_ KeyProvider = (*keytab.Keytab)(nil)
)
