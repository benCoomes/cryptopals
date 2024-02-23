package set02

import (
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	mathrand "math/rand"

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

func RandomAES128Key() ([]byte, error) {
	return randomBytes(16)
}

type Mode int

const (
	ECB Mode = iota
	CBC
)

func RandomEncrypt(plaintext []byte) ([]byte, Mode, error) {
	plaintext, err := wrapRandom(plaintext, 5, 10)
	if err != nil {
		return nil, 0, err
	}

	plaintext, err = PadPlaintext(plaintext, aes.BlockSize)
	if err != nil {
		return nil, 0, err
	}

	key, err := RandomAES128Key()
	if err != nil {
		return nil, 0, err
	}

	switch mode := Mode(mathrand.Intn(2)); mode {
	case ECB:
		ciphertext, err := set01.EncryptAesEcb(plaintext, key)
		if err != nil {
			return nil, mode, err
		}

		return ciphertext, mode, nil
	case CBC:
		iv, err := randomBytes(16)
		if err != nil {
			return nil, mode, err
		}
		ciphertext, err := CBCEncrypt(plaintext, key, iv)
		if err != nil {
			return nil, mode, err
		}
		return ciphertext, mode, nil
	default:
		return nil, mode, fmt.Errorf("unrecognized encryption mode: %v", mode)
	}
}

type BlackBoxEncrypter func([]byte) ([]byte, error)

func PredictCipherMode(encrypter BlackBoxEncrypter) (Mode, error) {
	// make plaintext large enough to garuntee two blocks, regardless of added prefixes
	plaintext := make([]byte, aes.BlockSize*3)
	for i := range plaintext {
		plaintext[i] = 'A'
	}

	ciphertext, err := encrypter(plaintext)
	if err != nil {
		return 0, err
	}

	matches := set01.CountSameBlocks(ciphertext)
	if matches > 0 {
		return ECB, nil
	}

	return CBC, nil
}

func randomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := cryptorand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// returns []byte with [min, max] random bytes prepended to the front, and [min, max] random bytes appended to the end of input.
func wrapRandom(input []byte, minLen int, maxLen int) ([]byte, error) {
	appendLen := minLen + mathrand.Intn(maxLen-minLen+1)
	appendix, err := randomBytes(appendLen)
	if err != nil {
		return nil, err
	}

	prependLen := minLen + mathrand.Intn(maxLen-minLen+1)
	prependix, err := randomBytes(prependLen)
	if err != nil {
		return nil, err
	}

	input = append(input, appendix...)
	input = append(prependix, input...)
	return input, nil
}
