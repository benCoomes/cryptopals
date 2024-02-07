package set01

import (
	"encoding/base64"
	"errors"
	"math"
)

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

// input is a hex-encoded string. Output is a plaintext english string (hopefully) and the byte used to decrypt.
func DecryptSingleByteXorHexString(input string) (string, byte, error) {
	bytes, err := hexToBytes(input)
	if err != nil {
		return "", 0, err
	}

	decrypted, key := DecryptSingleByteXor(bytes)
	return decrypted, key, nil
}

func DecryptSingleByteXor(bytes []byte) (string, byte) {
	lowestScore := math.MaxFloat64
	bestResult := ""
	bestKey := byte(0x0)

	for v := 0; v < 256; v++ {
		key := []byte{byte(v)}
		decryptedHex := Xor(bytes, key)

		plaintext := string(decryptedHex)

		score := scorePlaintext(plaintext)
		if score < lowestScore {
			lowestScore = score
			bestResult = plaintext
			bestKey = byte(v)
		}

	}

	return bestResult, bestKey
}

// input is a slice of hex-encoded strings, output is (hopefully) an english plaintext string
func FindSingleCharXorEncryptedLine(input []string) (string, error) {
	result := ""
	lowestScore := math.MaxFloat64
	for _, line := range input {
		decrypted, _, err := DecryptSingleByteXorHexString(line)
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

func HammingDistanceString(input1 string, input2 string) (int, error) {
	bytes1, bytes2 := []byte(input1), []byte(input2)
	return HammingDistance(bytes1, bytes2)
}

func HammingDistance(bytes1 []byte, bytes2 []byte) (int, error) {
	if len(bytes1) != len(bytes2) {
		return 0, errors.New("inputs must have the same length in bytes")
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

func DecryptRepeatingKeyXor(input string) (string, string, error) {
	bytes, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return "", "", err
	}

	keysize, err := findKeysize(bytes, 2, 40)
	if err != nil {
		return "", "", err
	}

	result, key, err := decryptRepeatingKeyXorWithKeysize(bytes, keysize)
	if err != nil {
		return "", "", err
	}

	return result, key, nil
}

func findKeysize(bytes []byte, minGuess int, maxGuess int) (int, error) {
	if minGuess <= 0 || maxGuess < minGuess {
		return 0, errors.New("minGuess must be less than maxGuess, and both must be greater than zero")
	}

	if maxGuess*2 > len(bytes) {
		return 0, errors.New("maxGuess is too large to check against the given input")
	}

	bestKey := minGuess
	bestScore := math.MaxFloat64
	for keysize := minGuess; keysize <= maxGuess; keysize++ {
		tcount, tdist := 0, 0
		for i := 0; i+(keysize*2) < len(bytes); i += keysize * 2 {
			div := i + keysize
			b1, b2 := bytes[i:div], bytes[div:div+keysize]
			dist, err := HammingDistance(b1, b2)
			if err != nil {
				return 0, err
			}

			tdist += dist
			tcount += keysize
		}

		score := float64(tdist) / float64(tcount)
		if score < bestScore {
			bestScore = score
			bestKey = keysize
		}
	}

	return bestKey, nil
}

// takes input bytes that have been xord with key where only the keysize is known.
// returns the decrypted string and the key
func decryptRepeatingKeyXorWithKeysize(bytes []byte, keysize int) (string, string, error) {
	// break into keysize blocks, and interleave
	// decrypt each block as single-char xor, building the key and original text back from the result
	decrypted := make([]byte, len(bytes))
	block := make([]byte, len(bytes)/keysize+1)
	key := make([]byte, keysize)

	for b := 0; b < keysize; b++ {
		n := 0
		for i := b; i < len(bytes); i += keysize {
			block[n] = bytes[i]
			n++
		}

		dblock, keybyte := DecryptSingleByteXor(block)
		key[b] = keybyte
		n = 0
		for i := b; i < len(bytes); i += keysize {
			decrypted[i] = dblock[n]
			n++
		}
	}

	// return descrypted text and key
	return string(decrypted), string(key), nil
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
