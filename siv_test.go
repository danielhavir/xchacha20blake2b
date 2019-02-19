package xchacha20blake2b

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestXChaCha20Blake2bSIV(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)
	cphr, err := New(key)
	if err != nil {
		t.Error(err)
	}

	msg := make([]byte, 64)
	rand.Read(msg)
	aad := make([]byte, 16)
	rand.Read(aad)

	ct := cphr.Seal(nil, nil, msg, aad)
	pt, err := cphr.Open(nil, nil, ct, aad)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(msg, pt) {
		t.Error("plaintexts do not match")
	}

	_, err = cphr.Open(nil, nil, ct, nil)
	if err == nil {
		t.Error("incorrect additional data does not invalidate decryption")
	}

	cphr2, err := New(make([]byte, KeySize))
	if err != nil {
		t.Error(err)
	}
	_, err = cphr2.Open(nil, nil, ct, aad)
	if err == nil {
		t.Error("ciphertext can be decrypted with incorrect password")
	}
}
