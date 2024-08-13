package sec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
)

type P256Key struct {
	X []byte
	Y []byte
}

func (p *P256Key) ToCOSE() *COSEKey {
	return &COSEKey{
		KeyType:   2,
		Algorithm: -25,
		Parameters: map[uint16]any{
			wrapIntToUint16(-1): uint(1),
			wrapIntToUint16(-2): p.X,
			wrapIntToUint16(-3): p.Y,
		},
	}
}

func (p *P256Key) Bytes() []byte {
	data := make([]byte, 0, 65)
	data = append(data, 0x04)
	data = append(data, p.X...)
	data = append(data, p.Y...)
	return data
}

func P256FromCOSE(k *COSEKey) (*P256Key, error) {
	if k.KeyType != 2 || (k.Algorithm != -7 && k.Algorithm != -25) {
		return nil, fmt.Errorf("P256: invalid key type")
	}

	ok, curve := KeyParamAs[uint](k, -1)
	if !ok || curve != 1 {
		return nil, fmt.Errorf("P256FromCOSE: invalid curve type")
	}
	ok, x := KeyParamAs[[]byte](k, -2)
	if !ok {
		return nil, fmt.Errorf("P256FromCOSE: invalid key type")
	}
	ok, y := KeyParamAs[[]byte](k, -3)
	if !ok {
		return nil, fmt.Errorf("P256FromCOSE: invalid key type")
	}

	return &P256Key{
		X: x,
		Y: y,
	}, nil
}

func UnparsedPublicKey(curve elliptic.Curve, pubKeyBytes []byte) (*ecdsa.PublicKey, error) {
	if len(pubKeyBytes) != 65 || pubKeyBytes[0] != 4 {
		return nil, fmt.Errorf("invalid public key format")
	}

	x := new(big.Int).SetBytes(pubKeyBytes[1:33])
	y := new(big.Int).SetBytes(pubKeyBytes[33:65])

	publicKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	return publicKey, nil
}

func P256FromKey(public crypto.PublicKey) (*P256Key, error) {
	pub, ok := public.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("P256FromKey: unsupported key type")
	}
	ecdhPub, err := pub.ECDH()
	if err != nil {
		return nil, err
	}
	data := ecdhPub.Bytes()
	if len(data) != 65 || data[0] != 0x04 {
		return nil, fmt.Errorf("P256FromKey: invalid public key")
	}

	return &P256Key{
		X: data[1:33],
		Y: data[33:65],
	}, nil
}
