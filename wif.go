// Copyright (c) 2013, 2014 The btcsuite developers
// Copyright (c) 2015 The Decred Developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/decred/dcrutil"
	"github.com/decred/dcrutil/base58"
)

// ErrMalformedPrivateKey describes an error where a WIF-encoded private
// key cannot be decoded due to being improperly formatted.  This may occur
// if the byte length is incorrect or an unexpected magic number was
// encountered.
var ErrMalformedPrivateKey = errors.New("malformed private key")

// WIF contains the individual components described by the Wallet Import Format
// (WIF).  A WIF string is typically used to represent a private key and its
// associated address in a way that  may be easily copied and imported into or
// exported from wallet software.  WIF strings may be decoded into this
// structure by calling DecodeWIF or created with a user-provided private key
// by calling NewWIF.
type WIF struct {
	// ecType is the type of ECDSA used.
	ecType int

	// PrivKey is the private key being imported or exported.
	PrivKey secp256k1.PrivateKey

	// netID is the network identifier byte used when
	// WIF encoding the private key.
	netID [2]byte
}

// NewWIF creates a new WIF structure to export an address and its private key
// as a string encoded in the Wallet Import Format.  The compress argument
// specifies whether the address intended to be imported or exported was created
// by serializing the public key compressed rather than uncompressed.
func NewWIF(privKey secp256k1.PrivateKey) *WIF {
	return &WIF{0, privKey, params.PrivateKeyID}
}

// DecodeWIF creates a new WIF structure by decoding the string encoding of
// the import format.
//
// The WIF string must be a base58-encoded string of the following byte
// sequence:
//
//  * 2 bytes to identify the network, must be 0x80 for mainnet or 0xef for
//    either testnet or the regression test network
//  * 1 extra byte
//  * 32 bytes of a binary-encoded, big-endian, zero-padded private key
//  * 4 bytes of checksum, must equal the first four bytes of the double SHA256
//    of every byte before the checksum in this sequence
//
// If the base58-decoded byte sequence does not match this, DecodeWIF will
// return a non-nil error.  ErrMalformedPrivateKey is returned when the WIF
// is of an impossible length.  ErrChecksumMismatch is returned if the
// expected WIF checksum does not match the calculated checksum.
func DecodeWIF(wif string) (*WIF, error) {
	decoded := base58.Decode(wif)
	decodedLen := len(decoded)

	if decodedLen != 39 {
		return nil, ErrMalformedPrivateKey
	}

	// Checksum is first four bytes of hash of the identifier byte
	// and privKey.  Verify this matches the final 4 bytes of the decoded
	// private key.
	cksum := chainhash.HashFuncB(decoded[:decodedLen-4])
	if !bytes.Equal(cksum[:4], decoded[decodedLen-4:]) {
		return nil, dcrutil.ErrChecksumMismatch
	}

	netID := [2]byte{decoded[0], decoded[1]}

	privKeyBytes := decoded[3 : 3+secp256k1.PrivKeyBytesLen]
	privKey, _ := secp256k1.PrivKeyFromBytes(curve, privKeyBytes)

	return &WIF{0, *privKey, netID}, nil
}

// String creates the Wallet Import Format string encoding of a WIF structure.
// See DecodeWIF for a detailed breakdown of the format and requirements of
// a valid WIF string.
func (w *WIF) String() string {
	// Precalculate size.  Maximum number of bytes before base58 encoding
	// is two bytes for the network, one byte for the ECDSA type, 32 bytes
	// of private key and finally four bytes of checksum.
	encodeLen := 2 + 1 + 32 + 4

	a := make([]byte, 0, encodeLen)
	a = append(a, w.netID[:]...)
	a = append(a, byte(w.ecType))
	a = append(a, w.PrivKey.Serialize()...)

	cksum := chainhash.HashFuncB(a)
	a = append(a, cksum[:4]...)
	return base58.Encode(a)
}

// SerializePubKey serializes the associated public key of the imported or
// exported private key in compressed format.  The serialization format
// chosen depends on the value of w.ecType.
func (w *WIF) SerializePubKey() []byte {
	pk := secp256k1.PublicKey{
		Curve: curve,
		X:     w.PrivKey.PublicKey.X,
		Y:     w.PrivKey.PublicKey.Y,
	}

	return pk.SerializeCompressed()
}

// paddedAppend appends the src byte slice to dst, returning the new slice.
// If the length of the source is smaller than the passed size, leading zero
// bytes are appended to the dst slice before appending src.
func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}
