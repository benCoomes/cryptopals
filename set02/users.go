package set02

import (
	"crypto/aes"
	"fmt"
	"math/rand"
	"strings"
	"sync"

	"github.com/benCoomes/cryptopals/set01"
)

// parse a KV string in the format:
// foo=bar&baz=2
// into
// {"foo" => "bar", "baz" => "2"}
func parseKVs(input string) (map[string]string, error) {
	pairs := strings.Split(input, "&")
	kv := make(map[string]string, len(pairs))
	for _, p := range pairs {
		split := strings.SplitN(p, "=", 2)
		if len(split) != 2 {
			return nil, fmt.Errorf("'%v' is not formatted correctly", input)
		}
		kv[split[0]] = split[1]
	}
	return kv, nil
}

// creates a profile for a user and returns a user profile, encoded as a KV string
func createProfile(email string) string {
	email = strings.ReplaceAll(email, "=", "_")
	email = strings.ReplaceAll(email, "&", "_")
	id := rand.Int()
	return fmt.Sprintf("email=%v&uid=%v&role=user", email, id)
}

func createEncryptedProfile(email string) ([]byte, error) {
	key, err := getUserEncryptionKey()
	if err != nil {
		return nil, err
	}

	profile := createProfile(email)
	padded, err := PadPlaintext([]byte(profile), aes.BlockSize)
	if err != nil {
		return nil, err
	}

	enc, err := set01.EncryptAesEcb(padded, key)
	if err != nil {
		return nil, err
	}
	return enc, nil
}

func decryptProfile(profile []byte) (map[string]string, error) {
	key, err := getUserEncryptionKey()
	if err != nil {
		return nil, err
	}

	padded, err := set01.DecodeAesEcb(profile, key)
	if err != nil {
		return nil, err
	}

	plaintext := RemovePadding(padded, aes.BlockSize)
	return parseKVs(string(plaintext))
}

func canAdmin(profile []byte) (bool, error) {
	dprofile, err := decryptProfile(profile)
	if err != nil {
		return false, err
	}

	return dprofile["role"] == "admin", nil
}

var key []byte
var keymu sync.Mutex

func getUserEncryptionKey() ([]byte, error) {
	if key != nil {
		return key, nil
	}

	keymu.Lock()
	defer keymu.Unlock()

	if key != nil {
		return key, nil
	}
	newKey, err := RandomAES128Key()
	if err != nil {
		return nil, err
	}
	key = newKey
	return key, nil
}
