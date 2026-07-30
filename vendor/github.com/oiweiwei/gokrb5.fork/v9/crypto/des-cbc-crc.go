package crypto

import (
	"crypto/des"
	"crypto/hmac"
	"errors"
	"hash"

	"github.com/oiweiwei/gokrb5.fork/v9/crypto/common"
	"github.com/oiweiwei/gokrb5.fork/v9/crypto/rfc3961"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/chksumtype"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/etypeID"
)

// RFC 3961 Section 6.2.3

// DesCbcCrc implements Kerberos encryption type des-cbc-md5.
type DesCbcCrc struct{}

// GetETypeID returns the EType ID number.
func (e DesCbcCrc) GetETypeID() int32 {
	return etypeID.DES_CBC_CRC
}

// GetHashID returns the checksum type ID number.
func (e DesCbcCrc) GetHashID() int32 {
	return chksumtype.CRC32
}

// GetKeyByteSize returns the number of bytes for key of this etype.
func (e DesCbcCrc) GetKeyByteSize() int {
	return 8
}

// GetKeySeedBitLength returns the number of bits for the seed for key generation.
func (e DesCbcCrc) GetKeySeedBitLength() int {
	return 64
}

// GetHashFunc returns the hash function for this etype.
func (e DesCbcCrc) GetHashFunc() func() hash.Hash {
	return rfc3961.NewCRC32
}

// GetMessageBlockByteSize returns the block size for the etype's messages.
func (e DesCbcCrc) GetMessageBlockByteSize() int {
	return des.BlockSize
}

// GetDefaultStringToKeyParams returns the default key derivation parameters in string form.
func (e DesCbcCrc) GetDefaultStringToKeyParams() string {
	var s string
	return s
}

// GetConfounderByteSize returns the byte count for confounder to be used during cryptographic operations.
func (e DesCbcCrc) GetConfounderByteSize() int {
	return des.BlockSize
}

// GetHMACBitLength returns the bit count size of the integrity hash.
func (e DesCbcCrc) GetHMACBitLength() int {
	return e.GetHashFunc()().Size() * 8
}

// GetCypherBlockBitLength returns the bit count size of the cypher block.
func (e DesCbcCrc) GetCypherBlockBitLength() int {
	return des.BlockSize * 8
}

// StringToKey returns a key derived from the string provided.
func (e DesCbcCrc) StringToKey(secret string, salt string, s2kparams string) ([]byte, error) {
	if s2kparams != "" {
		return []byte{}, errors.New("s2kparams must be an empty string")
	}
	return rfc3961.DESStringToKey(secret, salt, e)
}

// RandomToKey returns a key from the bytes provided.
func (e DesCbcCrc) RandomToKey(b []byte) []byte {
	return rfc3961.DESRandomToKey(b)
}

// DeriveRandom generates data needed for key generation.
func (e DesCbcCrc) DeriveRandom(protocolKey, usage []byte) ([]byte, error) {
	r, err := rfc3961.DeriveRandom(protocolKey, usage, e)
	return r, err
}

// DeriveKey derives a key from the protocol key based on the usage value.
func (e DesCbcCrc) DeriveKey(protocolKey, usage []byte) ([]byte, error) {
	r := make([]byte, len(protocolKey))
	copy(r, protocolKey)
	return r, nil
}

// EncryptData encrypts the data provided.
func (e DesCbcCrc) EncryptData(key, data []byte) ([]byte, []byte, error) {
	iv := make([]byte, des.BlockSize)
	copy(iv, key)
	return rfc3961.DESEncryptData(key, data, iv, e)
}

// EncryptMessage encrypts the message provided and concatenates it with the integrity hash to create an encrypted message.
func (e DesCbcCrc) EncryptMessage(key, message []byte, usage uint32) ([]byte, []byte, error) {
	return rfc3961.DESEncryptMessage(key, message, usage, e)
}

// DecryptData decrypts the data provided.
func (e DesCbcCrc) DecryptData(key, data []byte) ([]byte, error) {
	iv := make([]byte, des.BlockSize)
	copy(iv, key)
	return rfc3961.DESDecryptData(key, data, iv, e)
}

// DecryptMessage decrypts the message provided and verifies the integrity of the message.
func (e DesCbcCrc) DecryptMessage(key, ciphertext []byte, usage uint32) ([]byte, error) {
	return rfc3961.DESDecryptMessage(key, ciphertext, usage, e)
}

// VerifyIntegrity checks the integrity of the plaintext message.
func (e DesCbcCrc) VerifyIntegrity(protocolKey, ct, pt []byte, usage uint32) bool {
	return rfc3961.DESVerifyIntegrity(protocolKey, ct, pt, usage, e)
}

// GetChecksumHash returns a keyed checksum hash of the bytes provided.
func (e DesCbcCrc) GetChecksumHash(protocolKey, data []byte, usage uint32) ([]byte, error) {
	return rfc3961.DESGetHash(data, protocolKey, common.GetUsageKc(usage), e)
}

// VerifyChecksum compares the checksum of the message bytes is the same as the checksum provided.
func (e DesCbcCrc) VerifyChecksum(protocolKey, data, chksum []byte, usage uint32) bool {
	c, err := e.GetChecksumHash(protocolKey, data, usage)
	if err != nil {
		return false
	}
	return hmac.Equal(chksum, c)
}
