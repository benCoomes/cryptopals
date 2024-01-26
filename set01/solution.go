package set01

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math"
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

var byteToHex = map[byte]rune{
	0x0: '0',
	0x1: '1',
	0x2: '2',
	0x3: '3',
	0x4: '4',
	0x5: '5',
	0x6: '6',
	0x7: '7',
	0x8: '8',
	0x9: '9',
	0xa: 'a',
	0xb: 'b',
	0xc: 'c',
	0xd: 'd',
	0xe: 'e',
	0xf: 'f',
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

// modified from https://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
// we assume spaces have ~20% occurance and adjust other frequencies down.
// also, assume other symbols never appear as a heuristic to filter out symbol-heavy text.
var englishFrequencies = map[rune]float64{
	' ': 19.9,
	'e': 9.6,
	't': 7.3,
	'a': 6.5,
	'o': 6.1,
	'i': 5.8,
	'n': 5.6,
	's': 5.0,
	'r': 4.8,
	'h': 4.7,
	'd': 3.5,
	'l': 3.2,
	'u': 2.3,
	'c': 2.2,
	'm': 2.1,
	'f': 1.8,
	'y': 1.7,
	'w': 1.7,
	'g': 1.6,
	'p': 1.5,
	'b': 1.2,
	'v': 0.9,
	'k': 0.6,
	'x': 0.1,
	'q': 0.1,
	'j': 0.1,
	'z': 0.1,
	0:   0, // all other symbols are tracked here
}

func HexToBase64(input string) (string, error) {
	//return hexToBase64StdLib(input)
	return hexToBase64Custom(input)
}

// XORs bytes represented by input with bytes represented by secret
// if secret is shorter than input, the bytes in secret are repeated.
// if input is longer, additional bytes in the secret are ignored.
func HexXor(input string, secret string) (string, error) {
	inputBytes, err := hexToBytes(input)
	if err != nil {
		return "", err
	}
	secretBytes, err := hexToBytes(secret)
	if err != nil {
		return "", err
	}

	result := Xor(inputBytes, secretBytes)
	return bytesToHex(result), nil
}

// XORs input bytes with secret bytes
// if secret is shorter than input, the bytes in secret are repeated.
// if input is longer, additional bytes in the secret are ignored.
func Xor(input []byte, secret []byte) []byte {
	result := make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		result[i] = input[i] ^ secret[i%len(secret)]
	}
	return result
}

func HexToString(input string) (string, error) {
	bytes, err := hexToBytes(input)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

// input is a hex-encoded string. Output is a plaintext english string (hopefully) and the byte used to decrypt.
func DecryptSingleByteXor(input string) (string, byte, error) {
	lowestScore := math.MaxFloat64
	bestResult := ""
	bestKey := byte(0x0)

	for v := 0; v < 256; v++ {
		key := bytesToHex([]byte{byte(v)})
		decryptedHex, err := HexXor(input, key)
		if err != nil {
			return "", 0, err
		}

		plaintext, err := HexToString(decryptedHex)
		if err != nil {
			return "", 0, err
		}

		score := scorePlaintext(plaintext)
		if score < lowestScore {
			lowestScore = score
			bestResult = plaintext
			bestKey = byte(v)
		}

	}

	return bestResult, bestKey, nil
}

// input is a slice of hex-encoded strings, output is (hopefully) an english plaintext string
func FindSingleCharXorEncryptedLine(input []string) (string, error) {
	result := ""
	lowestScore := math.MaxFloat64
	for _, line := range input {
		decrypted, _, err := DecryptSingleByteXor(line)
		if err != nil {
			return "", err
		}
		score := scorePlaintext(decrypted)
		if score < lowestScore {
			lowestScore = score
			result = decrypted
		}
	}
	return result, nil
}

func EncryptRepeatingXOR(input string, secret string) string {
	bytes := Xor([]byte(input), []byte(secret))
	return bytesToHex(bytes)
}

func HammingDistance(input1 string, input2 string) (int, error) {
	bytes1, bytes2 := []byte(input1), []byte(input2)
	if len(bytes1) != len(bytes2) {
		return 0, errors.New("input strings must have the same length in bytes")
	}

	sum := 0
	for i := 0; i < len(bytes1); i++ {
		b1, b2 := bytes1[i], bytes2[i]
		diff := b1 ^ b2
		dist := (diff & 1) +
			((diff & 2) >> 1) +
			((diff & 4) >> 2) +
			((diff & 8) >> 3) +
			((diff & 16) >> 4) +
			((diff & 32) >> 5) +
			((diff & 64) >> 6) +
			((diff & 128) >> 7)
		sum += int(dist)
	}
	return sum, nil
}

// given an input string, return the mean squared error of character frequency
// lower scores indicate higher likelyhood that input is in English.
func scorePlaintext(input string) float64 {
	freqs := alphabetFrequency(input)
	var sumSquares float64 = 0
	for c, f := range freqs {
		sdiff := math.Pow(f-englishFrequencies[c], 2)
		sumSquares += sdiff
	}
	return sumSquares / float64(len(freqs))
}

// measures the frequency of characters in the input
// upercase and lowercase are counted the same: the returned map is keyed with lowercase
// spaces are also counted.
// all other symbols are counted together in the '0' key
func alphabetFrequency(input string) map[rune]float64 {
	counts := map[rune]int{
		' ': 0,
		'a': 0,
		'b': 0,
		'c': 0,
		'd': 0,
		'e': 0,
		'f': 0,
		'g': 0,
		'h': 0,
		'i': 0,
		'j': 0,
		'k': 0,
		'l': 0,
		'm': 0,
		'n': 0,
		'o': 0,
		'p': 0,
		'q': 0,
		'r': 0,
		's': 0,
		't': 0,
		'u': 0,
		'v': 0,
		'w': 0,
		'x': 0,
		'y': 0,
		'z': 0,
		0:   0,
	}

	for _, c := range input {
		// 65 - 90 : A - Z
		// 97 - 122 : a - z
		if 'A' <= c && c <= 'Z' {
			c = c + ('a' - 'A')
			counts[c] += 1
		} else if (97 <= c && c <= 122) || c == ' ' {
			counts[c] += 1
		} else {
			counts[0] += 1
		}
	}

	runeCount := float64(len([]rune(input)))
	freqs := make(map[rune]float64, len(counts))
	for k, v := range counts {
		freqs[k] = float64(v) / runeCount * 100
	}
	return freqs
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

func bytesToHex(bytes []byte) string {
	runes := make([]rune, len(bytes)*2)
	i := 0
	for _, b := range bytes {
		runes[i] = byteToHex[b>>4]
		runes[i+1] = byteToHex[b&0xf]
		i += 2
	}
	return string(runes)
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
