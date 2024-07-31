package sec

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

func EncryptAES256CBC(data []byte, key []byte) ([]byte, error) {
	if len(data) > 4096 {
		return nil, errors.New("data is too large")
	}

	bIV := make([]byte, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, bIV)
	mode.CryptBlocks(ciphertext, data)
	return ciphertext, nil
}

func DecryptAES256CBC(data, key []byte) ([]byte, error) {
	if len(data) > 4096 {
		return nil, errors.New("data is too large")
	}

	bIV := make([]byte, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(data))
	mode := cipher.NewCBCDecrypter(block, bIV)
	mode.CryptBlocks(ciphertext, data)
	return ciphertext, nil
}
