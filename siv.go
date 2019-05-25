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
const KeySize = 32
const chachaPolyNonceSize = 24

// xchacha20SIV
type xchacha20SIV struct {
	encKey, macKey []byte
}

// If x and y are non-negative integers, we define Z = toByte(x, y) to
// be the y-byte string containing the binary representation of x in
// big-endian byte order.
func toByte(x, y int) (z []byte) {
	z = make([]byte, y)
	ux := uint64(x)
	var xByte byte
	for i := y - 1; i >= 0; i-- {
		xByte = byte(ux)
		z[i] = xByte & 0xff
		ux = ux >> 8
	}
	return
}

// Expands an 32-byte array into a 64 byte array using the hashed key-derivation function
func expandSeed(seed []byte) (expanded []byte, err error) {
	expanded = make([]byte, 2*KeySize)
	h, err := blake2b.New256(seed)
	if err != nil {
		return
	}

	var ctr []byte
	var idx int
	for i := 0; i < 2; i++ {
		ctr = toByte(i, 32)
		idx = i * KeySize
		h.Write(ctr)
		h.Write(seed)
		copy(expanded[idx:idx+KeySize], h.Sum(nil))
	}
	return
}

// New returns a XChaCha20-Blake2b-SIV AEAD that uses the given 256-bit key
func New(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("xchacha20blake2b: bad key length")
	}

	key, err := expandSeed(key)
	if err != nil {
		return nil, err
	}

	return &xchacha20SIV{
		encKey: key[32:],
		macKey: key[:32],
	}, nil
}

// NonceSize returns the size of the nonce.
func (*xchacha20SIV) NonceSize() int {
	return 0
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
			return nil, fmt.Errorf("xchacha20blake2b: dst must be %d bytes long, received %d", msgLen, len(dst))
		}
		plaintext = dst
	} else {
		plaintext = make([]byte, msgLen)
	}
	nonce = make([]byte, chachaPolyNonceSize)
	copy(nonce, ciphertext[msgLen:msgLen+chachaPolyNonceSize])

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
		return nil, errors.New("xchacha20blake2b: authentication failed")
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
			panic(fmt.Sprintf("xchacha20blake2b: dst must be %d bytes long, received %d", msgLen+s.Overhead(), len(dst)))
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

	nonce = make([]byte, chachaPolyNonceSize)
	hash.Write(plaintext)
	hash.Write(additionalData)
	mac := hash.Sum(nil)
	copy(nonce, mac[:chachaPolyNonceSize])

	cphr, err := chacha20.NewCipher(nonce, s.encKey)
	if err != nil {
		panic(err)
	}

	cphr.XORKeyStream(ciphertext[:msgLen], plaintext)
	copy(ciphertext[msgLen:], mac)

	return
}
