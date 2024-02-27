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

// given an encryption function that encrypts:
// 1. With ECB
// 2. With the same key every time
// 3. With a secret message appended to the provided plaintext
// Discover what the secret message is and return it
func BreakECB(encrypter BlackBoxEncrypter) ([]byte, error) {
	blockSize, err := PredictBlockSize(encrypter)
	if err != nil {
		return nil, err
	}

	mode, err := PredictCipherMode(encrypter)
	if err != nil {
		return nil, err
	}
	if mode != ECB {
		return nil, errors.New("encrypter is not using ECB")
	}

	// Use known prefix to decrypt first block:
	// AAAAAAAS ecretMes sageHere
	// AAAAAASe cretMess ageHereX
	// AAAAASec retMessa geHereXX
	// ...
	// SecretMe ssageHer eXXXXXXX

	// Now we know first block: 'SecretMe'. Use that to decrypt second block:
	// AAAAAAAS ecretMes sageHere
	// AAAAAASe cretMess ageHereX
	// AAAAASec retMessa geHereXX
	// ...

	// start decoded with a block worth (minus one byte) of known values. We will remove them later.
	decoded := make([]byte, blockSize-1)
	for i := range decoded {
		decoded[i] = 'a'
	}

	shiftedCiphertexts := make(map[int][]byte, blockSize)
	messageLen := 0
	lastLen := 0
	for shift := 0; shift < blockSize; shift++ {
		prefix := decoded[0:shift]
		ciphertext, err := encrypter(prefix)
		if err != nil {
			return nil, err
		}
		shiftedCiphertexts[shift] = ciphertext

		if shift == 0 {
			// edge case: message is one byte over block size.
			// In this case prefix will grow to replace the padding, but never increase ciphertext size.
			// We will never hit the condition below, so set the messageLen here
			messageLen = len(ciphertext) - blockSize + 1
		} else if lastLen < len(ciphertext) {
			// When we detect the block size has grown,
			// we know that (shift-1) extra bytes made the (prefix+message)%blockSize = 0.
			// So, the message length is len(shiftedCiphertexts[shift-1]) - (shift-1)
			messageLen = len(shiftedCiphertexts[shift-1]) - (shift - 1)
		}

		lastLen = len(ciphertext)
	}

	for i := 0; i < messageLen; i++ {
		block := i / blockSize
		shift := blockSize - 1 - (i % blockSize)
		ciphertext := shiftedCiphertexts[shift]
		plaintext := decoded[len(decoded)-(blockSize-1):]
		guess, err := guessLastByte(plaintext, ciphertext[block*blockSize:(block+1)*blockSize], encrypter)
		if err != nil {
			return nil, err
		}
		decoded = append(decoded, guess)
	}

	return decoded[blockSize-1:], nil
}

func guessLastByte(prefix []byte, expected []byte, encrypter BlackBoxEncrypter) (byte, error) {
	// iterate all possible last bytes until a match is found for first block of ciphertext
	for b := 0; b < 256; b++ {
		guessPt := append(prefix, byte(b))
		guessCt, err := encrypter(guessPt)
		if err != nil {
			return 0, err
		}
		// comparing encrypt("AAAAAAA<b>") to encrypt("AAAAAAA<?>") (if 8 byte blocks)
		// if match, we know first byte of secret message is b
		if sliceEqual(guessCt[0:len(expected)], expected) {
			return byte(b), nil
		}

	}

	return 0, fmt.Errorf("did not find any guess that matched: %v", prefix)
}

func sliceEqual[K comparable, S []K](a S, b S) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for i, aval := range a {
		if b[i] != aval {
			return false
		}
	}

	return true
}

// given an unknown encryption function, returns the block size in bytes
func PredictBlockSize(encrypter BlackBoxEncrypter) (int, error) {
	// encypter is adding some unknown data, so we can't just see how long the ciphertext is for a single byte
	// we can see how long with 0 additional? 1 additional?
	// it will be the same length until we go over the block size
	// so if 1 extra byte yields N extra bytes of ciphertext from last encryption, we know block size is N bytes
	plaintext := []byte("")
	ciphertext, err := encrypter(plaintext)
	if err != nil {
		return 0, err
	}

	lastLen := len(ciphertext)
	maxBlockSize := 1024 // higher than any common block cipher's size
	for i := 1; i <= maxBlockSize; i++ {
		plaintext = append(plaintext, 'a')
		ciphertext, err := encrypter(plaintext)
		if err != nil {
			return 0, err
		}

		if len(ciphertext) > lastLen {
			return len(ciphertext) - lastLen, nil
		}
	}

	return 0, fmt.Errorf("unable to determine block size (stopped searching after %v bytes)", maxBlockSize)
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
