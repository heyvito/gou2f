package sec

import (
	"bytes"
	"github.com/heyvito/gou2f/cbor"
	"unsafe"
)

func NewCOSEKeyFromCBOR(m cbor.Map) *COSEKey {
	k := COSEKey{
		Parameters: make(map[uint16]any),
	}
	for _, i := range m {
		switch i.Key {
		case uint(1):
			// Table 21: Key Type Values
			// 1: kty
			//      1: OKP (Octet Key Pair) → need x
			//      2: EC2 (Double Coordinate Curves) → need x&y
			k.KeyType = uint16(i.Value.(uint))

		case uint(3): // kid
			// 3: alg
			//       -7: ES256
			//       -8: EdDSA
			//      -25: ECDH-ES + HKDF-256
			//      -35: ES384
			//      -36: ES512
			k.Algorithm = int32(i.Value.(int))
		case int(-1):
			// Table 22: Elliptic Curves
			// -1: Curves
			//      1: P-256(EC2)
			//      6: Ed25519(OKP)
			k.Parameters[wrapIntToUint16(-1)] = i.Value.(uint)
		case int(-2), int(-3):
			k.Parameters[wrapIntToUint16(i.Key.(int))] = i.Value.([]byte)
		}
	}

	return &k
}

func wrapIntToUint16(v int) uint16 { return *(*uint16)(unsafe.Pointer(&v)) }

type COSEKey struct {
	KeyType    uint16
	Algorithm  int32
	Parameters map[uint16]any
}

func KeyParamAs[T any](k *COSEKey, paramID int) (ok bool, res T) {
	var raw any
	raw, ok = k.Parameters[wrapIntToUint16(paramID)]
	if !ok {
		return
	}
	if v, ok := raw.(T); ok {
		return true, v
	}

	ok = false
	return
}

func (k *COSEKey) PublicKeyDER() []byte {
	switch k.KeyType {
	case 1:
		// ED25519
		// OKP -> Needs X
		if raw, ok := k.Parameters[wrapIntToUint16(-2)]; ok {
			if b, ok := raw.([]byte); ok {
				return b
			}
		}
	case 2:
		// ECDSA256
		// EC2 -> Needs X & Y
		buf := bytes.NewBuffer(nil)
		buf.WriteByte(0x04) // Octet String
		rawX, ok := k.Parameters[wrapIntToUint16(-2)]
		if !ok {
			break
		}

		rawY, ok := k.Parameters[wrapIntToUint16(-3)]
		if !ok {
			break
		}

		x, ok := rawX.([]byte)
		if !ok {
			break
		}

		y, ok := rawY.([]byte)
		if !ok {
			break
		}

		buf.Write(x)
		buf.Write(y)

		return buf.Bytes()
	}

	return nil
}
