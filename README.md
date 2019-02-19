![tests-passing](https://danielhavir.github.io/badges/7b10a2ec99832a186dac8cc279a45d3e/tests_passing.svg)

# AEAD: XChaCha20-Blake2b SIV
This project implements the XChaCha20-Blake2b in the synthetic IV constructions (MAC-then-encrypt) autheticated encryption construction with extended 192-bit nonce.

## Install
* Run `go get -u https://github.com/danielhavir/xchacha20blake2b`

## Example
```go
package main

import (
    "fmt"
    "crypto/rand"

    xchacha20blake2b "github.com/danielhavir/xchacha20blake2b"
)

func main() {
    // message
    msg := ...
    // additional data
    aad := ...
    // key must be 64 bytes long
    key := ...

    // create the AEAD
    cphr, err := xchacha20blake2b.New(key)
    if err != nil {
        panic(err)
    }

    // Encrypt
    ct := cphr.Seal(nil, nil, msg, aad)

    // Decrypt
    pt, err := cphr.Open(nil, nil, ct, aad)
    if err != nil {
        panic(err)
    }

    if !bytes.Equal(msg, pt) {
        panic("plaintexts do not match")
    }
}
```

## References
* Go [crypto blake2b package](https://godoc.org/golang.org/x/crypto/blake2b)
* Andreas Auernhammer, Go [chacha20 package](https://github.com/aead/chacha20)
