package messages

import (
	"fmt"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/oiweiwei/gokrb5.fork/v9/asn1tools"
	"github.com/oiweiwei/gokrb5.fork/v9/crypto"
	"github.com/oiweiwei/gokrb5.fork/v9/iana"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/asnAppTag"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/keyusage"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/msgtype"
	"github.com/oiweiwei/gokrb5.fork/v9/krberror"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
)

// APRep implements RFC 4120 KRB_AP_REP: https://tools.ietf.org/html/rfc4120#section-5.5.2.
type APRep struct {
	PVNO             int                 `asn1:"explicit,tag:0"`
	MsgType          int                 `asn1:"explicit,tag:1"`
	EncPart          types.EncryptedData `asn1:"explicit,tag:2"`
	DecryptedEncPart EncAPRepPart        `asn1:"optional"`
}

// EncAPRepPart is the encrypted part of KRB_AP_REP.
type EncAPRepPart struct {
	CTime          time.Time           `asn1:"generalized,explicit,tag:0"`
	Cusec          int                 `asn1:"explicit,tag:1"`
	Subkey         types.EncryptionKey `asn1:"optional,explicit,tag:2"`
	SequenceNumber int64               `asn1:"optional,explicit,tag:3"`
}

// encryptAPRepPart encrypts the EncAPRepPart struct.
func encryptAPRepPart(part EncAPRepPart, sessionKey types.EncryptionKey) (types.EncryptedData, error) {
	b, err := part.Marshal()
	if err != nil {
		return types.EncryptedData{}, krberror.Errorf(err, krberror.EncodingError, "error marshalling EncAPRepPart")
	}
	ed, err := crypto.GetEncryptedData(b, sessionKey, keyusage.AP_REP_ENCPART, 0)
	if err != nil {
		return ed, krberror.Errorf(err, krberror.EncryptingError, "error encrypting EncAPRepPart")
	}
	return ed, nil
}

// NewEncAPRepPart creates a new EncAPRepPart struct.
func NewEncAPRepPart(seq int64) EncAPRepPart {
	ctime := time.Now().UTC()
	return EncAPRepPart{
		CTime:          ctime,
		Cusec:          int((ctime.UnixNano() / int64(time.Microsecond)) - (ctime.Unix() * 1e6)),
		SequenceNumber: seq,
	}
}

// NewAPRep generates a new KRB_AP_REP struct.
func NewAPRep(sessionKey types.EncryptionKey, part EncAPRepPart) (APRep, error) {
	ed, err := encryptAPRepPart(part, sessionKey)
	if err != nil {
		return APRep{}, krberror.Errorf(err, krberror.KRBMsgError, "error creating EncAPRepPart for AP_REP")
	}
	return APRep{
		PVNO:    iana.PVNO,
		MsgType: msgtype.KRB_AP_REP,
		EncPart: ed,
	}, nil
}

// Marshal the APRep struct.
func (a *APRep) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(*a)
	if err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "AP_REP marshal error")
	}
	return asn1tools.AddASNAppTag(b, asnAppTag.APREP), nil
}

// Unmarshal bytes b into the APRep struct.
func (a *APRep) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, a, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.APREP))
	if err != nil {
		return processUnmarshalReplyError(b, err)
	}
	expectedMsgType := msgtype.KRB_AP_REP
	if a.MsgType != expectedMsgType {
		return krberror.NewErrorf(krberror.KRBMsgError, "message ID does not indicate a KRB_AP_REP. Expected: %v; Actual: %v", expectedMsgType, a.MsgType)
	}
	return nil
}

// DecryptPart decrypts the Part within the AP_REP.
func (a *APRep) DecryptEncPart(sessionKey types.EncryptionKey) error {
	b, err := crypto.DecryptEncPart(a.EncPart, sessionKey, keyusage.AP_REP_ENCPART)
	if err != nil {
		return err
	}
	return a.DecryptedEncPart.Unmarshal(b)
}

// Unmarshal bytes b into the APRep encrypted part struct.
func (a *EncAPRepPart) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, a, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.EncAPRepPart))
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "AP_REP unmarshal error")
	}
	return nil
}

// Marshal the EncAPRepPart.
func (a *EncAPRepPart) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(*a)
	if err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "AP_REP marshal error")
	}
	return asn1tools.AddASNAppTag(b, asnAppTag.EncAPRepPart), nil
}
