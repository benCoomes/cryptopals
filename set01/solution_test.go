package set01

import (
	"bufio"
	"os"
	"testing"
)

func Test_Challenge_01(t *testing.T) {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	actual, err := HexToBase64(input)
	assertNoError(t, err)

	if expected != actual {
		t.Errorf("Expected %v, got %v", expected, actual)
	}
}

func Test_Challenge_01_Padding1(t *testing.T) {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f"
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb28="
	actual, err := HexToBase64(input)
	assertNoError(t, err)

	if expected != actual {
		t.Errorf("Expected %v, got %v", expected, actual)
	}
}

func Test_Challenge_01_Padding2(t *testing.T) {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f"
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hybw=="
	actual, err := HexToBase64(input)
	assertNoError(t, err)

	if expected != actual {
		t.Errorf("Expected %v, got %v", expected, actual)
	}
}

func TestChallenge_02(t *testing.T) {
	input1 := "1c0111001f010100061a024b53535009181c"
	input2 := "686974207468652062756c6c277320657965"
	expected := "746865206b696420646f6e277420706c6179"
	actual, err := HexXor(input1, input2)
	assertNoError(t, err)

	if actual != expected {
		t.Errorf("Expected %v, got %v", expected, actual)
	}
}

func TestChallenge_03(t *testing.T) {
	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	expected := "Cooking MC's like a pound of bacon"
	plaintext, key, err := DecryptSingleByteXor(input)
	assertNoError(t, err)

	t.Logf("Key is %v, message is %v", key, plaintext)
	if plaintext != expected {
		t.Errorf("Expected %v, got %v", expected, plaintext)
	}
}

func TestChallenge04(t *testing.T) {
	input, err := readFile("./inputs/challenge_04.txt")
	expected := "Now that the party is jumping\n"
	assertNoError(t, err)

	decryptedLine, err := FindSingleCharXorEncryptedLine(input)
	assertNoError(t, err)

	if decryptedLine != expected {
		t.Errorf("Expected %v, got %v", expected, decryptedLine)
	}
}

func TestChallenge05(t *testing.T) {
	input := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	encrypted := EncryptRepeatingXOR(input, "ICE")
	if encrypted != expected {
		t.Errorf("Expected %v, got %v", expected, encrypted)
	}
}

func assertNoError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("Error raised: %v", err)
	}
}

func readFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lines := make([]string, 0)
	// warning: lines over 64K will be incomplete
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}
