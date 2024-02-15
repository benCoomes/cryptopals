package set02

import (
	"encoding/base64"
	"testing"

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
