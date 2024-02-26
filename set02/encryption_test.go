package set02

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/benCoomes/cryptopals/set01"
	"github.com/benCoomes/cryptopals/util"
)

func TestPadPlaintext(t *testing.T) {
	padded, err := PadPlaintext([]byte{0, 1, 2, 3}, 5)
	util.RefuteError(t, err)
	util.AssertSliceEqual(t, []byte{0, 1, 2, 3, 1}, padded)

	padded, err = PadPlaintext([]byte{0, 1, 2}, 8)
	util.RefuteError(t, err)
	util.AssertSliceEqual(t, []byte{0, 1, 2, 5, 5, 5, 5, 5}, padded)

	padded, err = PadPlaintext([]byte{0, 1, 2}, 1)
	util.RefuteError(t, err)
	util.AssertSliceEqual(t, []byte{0, 1, 2}, padded)

	_, err = PadPlaintext([]byte{0, 1, 2}, 0)
	util.AssertError(t, err)

	_, err = PadPlaintext([]byte{0, 1, 2}, -1)
	util.AssertError(t, err)
}

func TestCBCRoundTrip(t *testing.T) {
	message := []byte("0123456789abcde 0123456789abcde - Bagels are boiled and also baked.")
	key := []byte("YELLOW SUBMARINE")
	iv := []byte("APPLES & ORANGES")

	sysEncrypted, err := SystemCBCEncrypt(message, key, iv)
	util.RefuteError(t, err)
	sysDecrypted, err := SystemCBCDecrypt(sysEncrypted, key, iv)
	util.RefuteError(t, err)

	ciphertext, err := CBCEncrypt(message, key, iv)
	util.RefuteError(t, err)
	util.AssertSliceEqual(t, sysEncrypted, ciphertext)

	plaintext, err := CBCDecrypt(ciphertext, key, iv)
	util.RefuteError(t, err)
	util.RefuteSliceEqual(t, plaintext, ciphertext)
	util.AssertSliceEqual(t, message, plaintext)
	util.AssertSliceEqual(t, sysDecrypted, plaintext)
}

func TestChallenge10(t *testing.T) {
	expected := "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell"
	key := []byte("YELLOW SUBMARINE")
	iv := []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	bytesBase64, err := util.ReadFileBytes("./inputs/challenge10.txt")
	util.RefuteError(t, err)

	bytes := make([]byte, base64.StdEncoding.DecodedLen(len(bytesBase64)))
	_, err = base64.StdEncoding.Decode(bytes, bytesBase64)
	util.RefuteError(t, err)

	plaintext, err := CBCDecrypt(bytes, key, iv)
	util.RefuteError(t, err)
	util.AssertEqual(t, expected, string(plaintext)[0:len(expected)])
}

func TestRandomEncrypter(t *testing.T) {
	ciphertexts := make(map[int][]byte)
	modes := make(map[int]Mode)
	plaintext := []byte("This text has zero seasoning.")
	for i := 0; i < 100; i++ {
		ciphertext, mode, err := RandomEncrypt(plaintext)
		util.RefuteError(t, err)
		ciphertexts[i] = ciphertext
		modes[i] = mode
	}

	cbcCount := 0
	if modes[0] == CBC {
		cbcCount++
	}
	for i := 1; i < len(ciphertexts); i++ {
		util.RefuteSliceEqual(t, ciphertexts[0], ciphertexts[i])
		if modes[i] == CBC {
			cbcCount++
		}
	}
	util.RefuteEqual(t, 100, cbcCount)
	util.RefuteEqual(t, 0, cbcCount)
}

func TestPredictCipherMode(t *testing.T) {
	var expectedMode Mode
	testEncrypter := func(plaintext []byte) ([]byte, error) {
		ciphertext, mode, err := RandomEncrypt(plaintext)
		if err != nil {
			return nil, err
		}
		expectedMode = mode
		return ciphertext, nil
	}

	for i := 0; i < 100; i++ {
		predictedMode, err := PredictCipherMode(testEncrypter)
		util.RefuteError(t, err)

		if predictedMode != expectedMode {
			t.Fatalf("Failed to predict cipher mode on round %v. Expected %v, got %v", i, expectedMode, predictedMode)
		}
	}

}

func TestBreakECB(t *testing.T) {
	base64Message := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	secretMessage, err := base64.StdEncoding.DecodeString(base64Message)
	util.RefuteError(t, err)
	secretKey, err := RandomAES128Key()
	util.RefuteError(t, err)

	// appends the secret message to the provided plaintext before
	// encrypting with the secret (to the deciphering code) key
	testEncrypter := func(plaintext []byte) ([]byte, error) {
		plaintext = append(plaintext, secretMessage...)
		plaintext, err = PadPlaintext(plaintext, aes.BlockSize)
		if err != nil {
			return nil, err
		}

		ciphertext, err := set01.EncryptAesEcb(plaintext, secretKey)
		if err != nil {
			return nil, err
		}
		return ciphertext, nil
	}

	decoded, err := BreakECB(testEncrypter)
	util.RefuteError(t, err)
	// util.AssertSliceEqual(t, secretMessage, decoded)
	fmt.Printf("The secret message is: %v", decoded)
}
