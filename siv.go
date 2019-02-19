package xchacha20blake2b

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/aead/chacha20"
	"golang.org/x/crypto/blake2b"
)

// KeySize specifies the expected size of the key in bytes
const KeySize = 64

// xchacha20SIV
type xchacha20SIV struct {
	encKey, macKey []byte
}

// New is a constructor for the XChaCha20Blake2b-SIV
func New(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("Key is not 64 bytes")
	}
	return &xchacha20SIV{
		encKey: key[32:],
		macKey: key[:32],
	}, nil
}

// NonceSize returns the size of the nonce.
func (*xchacha20SIV) NonceSize() int {
	return 24
}

// Overhead returns the maximum difference between the lengths of a
// plaintext and its ciphertext.
func (*xchacha20SIV) Overhead() int {
	return blake2b.Size256
}

// Open decrypts and authenticates ciphertext, authenticates the
// additional data and, if successful, appends the resulting plaintext
// to dst, returning the updated slice. Nonce is expected to be empty or nil,
// since in the SIV construction, the first NonceSize() bytes of the authentication
// tag are used as the nonce.
func (s *xchacha20SIV) Open(dst, nonce, ciphertext, additionalData []byte) (plaintext []byte, err error) {
	msgLen := len(ciphertext) - s.Overhead()
	if dst != nil {
		if len(dst) != msgLen {
			return nil, fmt.Errorf("dst must be %d bytes long, received %d", msgLen, len(dst))
		}
		plaintext = dst
	} else {
		plaintext = make([]byte, msgLen)
	}
	nonce = make([]byte, s.NonceSize())
	copy(nonce, ciphertext[msgLen:msgLen+s.NonceSize()])

	cphr, err := chacha20.NewCipher(nonce, s.encKey)
	if err != nil {
		return
	}

	cphr.XORKeyStream(plaintext, ciphertext[:msgLen])

	hash, err := blake2b.New256(s.macKey)
	if err != nil {
		return
	}
	hash.Write(plaintext)
	hash.Write(additionalData)
	mac := hash.Sum(nil)

	if !bytes.Equal(mac, ciphertext[msgLen:]) {
		return nil, errors.New("authentication failed")
	}

	return
}

// Seal encrypts and authenticates plaintext, authenticates the
// additional data and appends the result to dst, returning the updated
// slice. Nonce is expected to be empty or nil, since in the SIV construction,
// the first NonceSize() bytes of the authentication tag are used as the nonce.
func (s *xchacha20SIV) Seal(dst, nonce, plaintext, additionalData []byte) (ciphertext []byte) {
	msgLen := len(plaintext)
	if dst != nil {
		if len(dst) != msgLen+s.Overhead() {
			panic(fmt.Sprintf("dst must be %d bytes long, received %d", msgLen+s.Overhead(), len(dst)))
		} else {
			ciphertext = dst
		}
	} else {
		ciphertext = make([]byte, msgLen+s.Overhead())
	}
	hash, err := blake2b.New256(s.macKey)
	if err != nil {
		panic(err)
	}

	nonce = make([]byte, s.NonceSize())
	hash.Write(plaintext)
	hash.Write(additionalData)
	mac := hash.Sum(nil)
	copy(nonce, mac[:s.NonceSize()])

	cphr, err := chacha20.NewCipher(nonce, s.encKey)
	if err != nil {
		panic(err)
	}

	cphr.XORKeyStream(ciphertext[:msgLen], plaintext)
	copy(ciphertext[msgLen:], mac)

	return
}
