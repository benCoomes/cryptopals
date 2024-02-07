package set01

import (
	"testing"
)

func TestChallenge_02(t *testing.T) {
	input1 := "1c0111001f010100061a024b53535009181c"
	input2 := "686974207468652062756c6c277320657965"
	expected := "746865206b696420646f6e277420706c6179"
	actual, err := HexXor(input1, input2)
	assertNoError(t, err)
	assertEqual(t, expected, actual)
}

func TestChallenge_03(t *testing.T) {
	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	expected := "Cooking MC's like a pound of bacon"
	plaintext, _, err := DecryptSingleByteXorHexString(input)
	assertNoError(t, err)
	assertEqual(t, expected, plaintext)
}

func TestChallenge04(t *testing.T) {
	input, err := readFile("./inputs/challenge_04.txt")
	expected := "Now that the party is jumping\n"
	assertNoError(t, err)

	decryptedLine, err := FindSingleCharXorEncryptedLine(input)
	assertNoError(t, err)
	assertEqual(t, expected, decryptedLine)
}

func TestChallenge05(t *testing.T) {
	input := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	encrypted := EncryptRepeatingXOR(input, "ICE")
	assertEqual(t, expected, encrypted)
}

func TestChallenge06_HammingDistance(t *testing.T) {
	s1 := "this is a test"
	s2 := "wokka wokka!!!"
	expected := 37
	distance, err := HammingDistanceString(s1, s2)
	assertNoError(t, err)
	assertEqual(t, expected, distance)
}

func TestChallenge06(t *testing.T) {
	lines, err := readFile("./inputs/challenge_06.txt")
	assertNoError(t, err)

	input := ""
	for _, line := range lines {
		input += line
	}

	expectedKey, expectedMsg := "Terminator X: Bring the noise", "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell"

	message, key, err := DecryptRepeatingKeyXor(input)
	assertNoError(t, err)
	assertEqual(t, expectedKey, key)
	assertEqual(t, expectedMsg, message[0:len(expectedMsg)])
}
