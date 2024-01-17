package set01

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
)

var hexToByte = map[rune]byte{
	'0': 0x0,
	'1': 0x1,
	'2': 0x2,
	'3': 0x3,
	'4': 0x4,
	'5': 0x5,
	'6': 0x6,
	'7': 0x7,
	'8': 0x8,
	'9': 0x9,
	'a': 0xa,
	'A': 0xa,
	'b': 0xb,
	'B': 0xb,
	'c': 0xc,
	'C': 0xc,
	'd': 0xd,
	'D': 0xd,
	'e': 0xe,
	'E': 0xe,
	'f': 0xf,
	'F': 0xf,
}

func HexToBase64(input string) (string, error) {
	//return hexToBase64StdLib(input)
	return hexToBase64Custom(input)
}

func hexToBase64StdLib(input string) (string, error) {
	bytes, err := hex.DecodeString(input)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(bytes), nil
}

func hexToBase64Custom(input string) (string, error) {
	runes := []rune(input)
	runeLen := len(runes)
	if runeLen%2 != 0 {
		return "", errors.New("invalid hex string - length is not a multiple of 2")
	}

	bytes := make([]byte, runeLen/2)
	b := 0
	for i := 0; i < runeLen; i += 2 {
		// potential 'not found' error here
		bytes[b] = hexToByte[runes[i]]<<4 | hexToByte[runes[i+1]]
		b += 1
	}
	// todo: byte to base64 map
	return base64.StdEncoding.EncodeToString(bytes), nil
}
