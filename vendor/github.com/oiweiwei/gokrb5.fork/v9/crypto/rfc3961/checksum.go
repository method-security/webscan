package rfc3961

import (
	"crypto/md5"

	"github.com/oiweiwei/gokrb5.fork/v9/crypto/etype"
)

func DesMacMd5(data, protocolKey []byte, usage []byte, e etype.EType) ([]byte, error) {
	iH := md5.New()
	iH.Write(data)
	cksum, _, err := e.EncryptData(protocolKey, iH.Sum(nil))
	if err != nil {
		return nil, err
	}
	return cksum, nil
}

func DESGetHash(data, protocolKey []byte, usage []byte, e etype.EType) ([]byte, error) {
	h := e.GetHashFunc()()
	h.Write(data)
	return h.Sum(nil), nil
}
