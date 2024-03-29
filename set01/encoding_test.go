package set01

import (
	"testing"

	"github.com/benCoomes/cryptopals/util"
)

func Test_Challenge_01(t *testing.T) {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	actual, err := HexToBase64(input)
	util.RefuteError(t, err)
	util.AssertEqual(t, expected, actual)
}

func Test_Challenge_01_Padding1(t *testing.T) {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f"
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb28="
	actual, err := HexToBase64(input)
	util.RefuteError(t, err)
	util.AssertEqual(t, expected, actual)
}

func Test_Challenge_01_Padding2(t *testing.T) {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f"
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hybw=="
	actual, err := HexToBase64(input)
	util.RefuteError(t, err)
	util.AssertEqual(t, expected, actual)
}
