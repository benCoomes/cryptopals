package set02

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/benCoomes/cryptopals/set01"
)

// pads to a multiple of blocksize using the PKCS#7 spec
func PadPlaintext(plaintext []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("block size must be greater than 0")
	}

	padLen := blockSize - (len(plaintext) % blockSize)

	if padLen == blockSize {
		return plaintext, nil
	}

	padding := make([]byte, padLen)
	for i := 0; i < padLen; i++ {
		padding[i] = byte(padLen)
	}

	return append(plaintext, padding...), nil
}

func RemovePadding(plaintext []byte, blockSize int) []byte {
	padLen := plaintext[len(plaintext)-1]
	if padLen >= byte(blockSize) || len(plaintext)%blockSize != 0 {
		return plaintext
	}

	padStart := len(plaintext) - int(padLen)
	for i := padStart; i < len(plaintext); i++ {
		if plaintext[i] != padLen {
			return plaintext
		}
	}

	return plaintext[0:padStart]
}

func CBCEncrypt(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
	if iv == nil || len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("iv must be %v bytes long", aes.BlockSize)
	}
	chain := iv

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	padded, err := PadPlaintext(plaintext, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(padded))
	for i := aes.BlockSize; i <= len(padded); i += aes.BlockSize {
		block := padded[i-aes.BlockSize : i]
		block = set01.Xor(block, chain)
		cipher.Encrypt(ciphertext[i-aes.BlockSize:i], block)
		chain = ciphertext[i-aes.BlockSize : i]
	}

	return ciphertext, nil
}

func CBCDecrypt(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
	if iv == nil || len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("iv must be %v bytes long", aes.BlockSize)
	}
	chain := iv

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	for i := aes.BlockSize; i <= len(ciphertext); i += aes.BlockSize {
		block := ciphertext[i-aes.BlockSize : i]
		cipher.Decrypt(plaintext[i-aes.BlockSize:i], block)
		fixed := set01.Xor(plaintext[i-aes.BlockSize:i], chain)
		copy(plaintext[i-aes.BlockSize:i], fixed)
		chain = block
	}

	unpadded := RemovePadding(plaintext, aes.BlockSize)
	return unpadded, nil
}

func SystemCBCEncrypt(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	encrypter := cipher.NewCBCEncrypter(c, iv)
	plaintext, err = PadPlaintext(plaintext, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext))
	encrypter.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

func SystemCBCDecrypt(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	decrypter := cipher.NewCBCDecrypter(c, iv)
	plaintext := make([]byte, len(ciphertext))
	decrypter.CryptBlocks(plaintext, ciphertext)

	return RemovePadding(plaintext, aes.BlockSize), nil
}
