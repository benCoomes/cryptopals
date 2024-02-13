package set02

import (
	"testing"

	"github.com/benCoomes/cryptopals/util"
)

func TestPadPlaintext(t *testing.T) {
	padded, err := PadPlaintext([]byte{0, 1, 2, 3}, 5)
	util.AssertNoError(t, err)
	util.AssertSliceEqual(t, []byte{0, 1, 2, 3, 1}, padded)

	padded, err = PadPlaintext([]byte{0, 1, 2}, 8)
	util.AssertNoError(t, err)
	util.AssertSliceEqual(t, []byte{0, 1, 2, 5, 5, 5, 5, 5}, padded)

	padded, err = PadPlaintext([]byte{0, 1, 2}, 1)
	util.AssertNoError(t, err)
	util.AssertSliceEqual(t, []byte{0, 1, 2}, padded)

	_, err = PadPlaintext([]byte{0, 1, 2}, 0)
	util.AssertError(t, err)

	_, err = PadPlaintext([]byte{0, 1, 2}, -1)
	util.AssertError(t, err)
}
