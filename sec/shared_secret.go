package sec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
)

type SharedSecret struct {
	PublicKey *COSEKey
	Secret    []byte
}

func deriveSharedSecret(private *ecdsa.PrivateKey, public *ecdsa.PublicKey) []byte {
	x, _ := public.Curve.ScalarMult(public.X, public.Y, private.D.Bytes())
	sharedSecret := sha256.Sum256(x.Bytes())
	return sharedSecret[:]
}

func NewSharedSecret(peerKey *COSEKey) (*SharedSecret, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	rawPeerPublic, err := P256FromCOSE(peerKey)
	if err != nil {
		return nil, err
	}

	peerPublic, err := UnparsedPublicKey(elliptic.P256(), rawPeerPublic.Bytes())
	if err != nil {
		return nil, err
	}

	sharedSecret := deriveSharedSecret(privateKey, peerPublic)

	publicP256, err := P256FromKey(privateKey.Public())
	if err != nil {
		return nil, err
	}
	return &SharedSecret{
		PublicKey: publicP256.ToCOSE(),
		Secret:    sharedSecret,
	}, nil
}

func (s *SharedSecret) EncryptPin(pin string) ([]byte, error) {
	return s.Encrypt([]byte(pin))
}

func (s *SharedSecret) Encrypt(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	message := hash[:16]
	enc, err := EncryptAES256CBC(message, s.Secret)
	if err != nil {
		return nil, err
	}
	return enc[:16], nil
}

func (s *SharedSecret) DecryptPinToken(data []byte) (*PinToken, error) {
	dec, err := DecryptAES256CBC(data, s.Secret)
	if err != nil {
		return nil, err
	}
	return &PinToken{dec}, nil
}
