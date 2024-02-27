package set02

import (
	"testing"

	"github.com/benCoomes/cryptopals/util"
)

func TestParseKV(t *testing.T) {
	input := "foo=bar&3=4&key=value"
	kvs, err := parseKVs(input)
	util.RefuteError(t, err)
	util.AssertEqual(t, "bar", kvs["foo"])
	util.AssertEqual(t, "4", kvs["3"])
	util.AssertEqual(t, "value", kvs["key"])
}

func TestCreateProfile(t *testing.T) {
	p1, err := parseKVs(createProfile("foo@bar.com"))
	util.RefuteError(t, err)
	util.AssertEqual(t, "foo@bar.com", p1["email"])
	util.AssertEqual(t, "user", p1["role"])
	util.AssertPresent(t, p1["uid"])

	p2, err := parseKVs(createProfile("controlchars=email.com&more"))
	util.RefuteError(t, err)
	util.AssertEqual(t, "controlchars_email.com_more", p2["email"])
}

func TestHackUserSystem(t *testing.T) {
	// goal: Create an input that will cause canAdmin(<encryptedProfile>) to return true
	// It will return true if, after decryption and parsing, the encrypted profile
	// contains the key-value "role=admin"

	// tools:
	// - A 'stolen' encrypted profile for an normal user (role=user).
	// - The createEncryptedProfile function, which creates and encrypts a profile for a new user, given an email.

	stolenProfile, err := createEncryptedProfile("foo@bar.com")
	util.RefuteError(t, err)

	hackProfile := stolenProfile // todo
	canAdmin, err := canAdmin(hackProfile)
	util.RefuteError(t, err)
	util.AssertEqual(t, true, canAdmin)
}
