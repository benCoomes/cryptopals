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

var byteToBase64 = map[byte]rune{
	0x00: 'A',
	0x01: 'B',
	0x02: 'C',
	0x03: 'D',
	0x04: 'E',
	0x05: 'F',
	0x06: 'G',
	0x07: 'H',
	0x08: 'I',
	0x09: 'J',
	0x0A: 'K',
	0x0B: 'L',
	0x0C: 'M',
	0x0D: 'N',
	0x0E: 'O',
	0x0F: 'P',
	0x10: 'Q',
	0x11: 'R',
	0x12: 'S',
	0x13: 'T',
	0x14: 'U',
	0x15: 'V',
	0x16: 'W',
	0x17: 'X',
	0x18: 'Y',
	0x19: 'Z',
	0x1A: 'a',
	0x1B: 'b',
	0x1C: 'c',
	0x1D: 'd',
	0x1E: 'e',
	0x1F: 'f',
	0x20: 'g',
	0x21: 'h',
	0x22: 'i',
	0x23: 'j',
	0x24: 'k',
	0x25: 'l',
	0x26: 'm',
	0x27: 'n',
	0x28: 'o',
	0x29: 'p',
	0x2A: 'q',
	0x2B: 'r',
	0x2C: 's',
	0x2D: 't',
	0x2E: 'u',
	0x2F: 'v',
	0x30: 'w',
	0x31: 'x',
	0x32: 'y',
	0x33: 'z',
	0x34: '0',
	0x35: '1',
	0x36: '2',
	0x37: '3',
	0x38: '4',
	0x39: '5',
	0x3A: '6',
	0x3B: '7',
	0x3C: '8',
	0x3D: '9',
	0x3E: '+',
	0x3F: '/',
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
	// todo: padding!
	bytes, err := hexToBytes(input)
	if err != nil {
		return "", err
	}

	return bytesToBase64(bytes)
}

func hexToBytes(input string) ([]byte, error) {
	runes := []rune(input)
	runeLen := len(runes)
	if runeLen%2 != 0 {
		return nil, errors.New("invalid hex string - length is not a multiple of 2")
	}

	bytes := make([]byte, runeLen/2)
	b := 0
	for i := 0; i < runeLen; i += 2 {
		// potential 'not found' error here
		bytes[b] = hexToByte[runes[i]]<<4 | hexToByte[runes[i+1]]
		b += 1
	}
	return bytes, nil
}

func bytesToBase64(bytes []byte) (string, error) {
	b64 := make([]rune, base64Len(bytes))
	b := 0
	for i := 0; i < len(bytes); i += 3 {
		// 11111100 00001111 11000000
		// 111111 000000 111111 000000
		// s1     s2     s3     s4

		// for the last triplet, there are either 1, 2, or 3 bytes.
		// 3 bytes proceeds as normal.
		// 2 bytes, we only have s1, s2, and s3 (bytes[i+2] does not exist, and should be replaced with 0's) s4 should be the padding char (=)
		// 1 byte, and we only have s1 and s2, but bytes[i+1] does not exist and should be 0's. s3 and s4 are '='.

		if i+1 >= len(bytes) {
			// 1 byte
			s1 := bytes[i] >> 2
			s2 := (bytes[i] & 0x3) << 4

			b64[b] = byteToBase64[s1]
			b64[b+1] = byteToBase64[s2]
			b64[b+2] = '='
			b64[b+3] = '='
		} else if i+2 >= len(bytes) {
			// 2 bytes
			s1 := bytes[i] >> 2
			s2 := (bytes[i]&0x3)<<4 | bytes[i+1]>>4
			s3 := (bytes[i+1] & 0xF) << 2

			b64[b] = byteToBase64[s1]
			b64[b+1] = byteToBase64[s2]
			b64[b+2] = byteToBase64[s3]
			b64[b+3] = '='
		} else {
			// 3 bytes
			s1 := bytes[i] >> 2
			s2 := (bytes[i]&0x3)<<4 | bytes[i+1]>>4
			s3 := (bytes[i+1]&0xF)<<2 | bytes[i+2]>>6
			s4 := bytes[i+2] & 0x3F

			b64[b] = byteToBase64[s1]
			b64[b+1] = byteToBase64[s2]
			b64[b+2] = byteToBase64[s3]
			b64[b+3] = byteToBase64[s4]
		}

		b += 4
	}

	return string(b64), nil
}

func base64Len(input []byte) int {
	length := len(input)
	if length%3 != 0 {
		// add room for padding chars
		length += 3 - length%3
	}
	// every three bytes result in four bas64 chars
	return length / 3 * 4
}
