package set02

import "errors"

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
