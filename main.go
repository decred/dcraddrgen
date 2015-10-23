// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/btcsuite/btcd/btcec"
)

var curve = btcec.S256()
var PrivateKeyID = PrivateKeyIDMain
var PubKeyHashAddrID = PubKeyHashAddrIDMain

// Flag arguments.
var testnet = flag.Bool("testnet", false, "")

func setupFlags(msg func(), f *flag.FlagSet) {
	f.Usage = msg
}

// generateKeyPair generates and stores a secp256k1 keypair in a file.
func generateKeyPair(filename string) error {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return err
	}
	pub := btcec.PublicKey{curve,
		key.PublicKey.X,
		key.PublicKey.Y}
	priv := btcec.PrivateKey{key.PublicKey, key.D}

	addr, err := NewAddressPubKeyHash(Hash160(pub.SerializeCompressed()))
	if err != nil {
		return err
	}

	privWif := NewWIF(priv)

	var buf bytes.Buffer
	buf.WriteString("Address: ")
	buf.WriteString(addr.EncodeAddress())
	buf.WriteString("\n")
	buf.WriteString("Private key: ")
	buf.WriteString(privWif.String())
	buf.WriteString("\n")

	err = ioutil.WriteFile(filename, buf.Bytes(), 0644)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	helpMessage := func() {
		fmt.Println("Usage: dcraddrgen [-testnet] [-h] filename")
		fmt.Println("Generate a Decred private and public key. These are " +
			"output to the file 'filename'.\n")
		fmt.Println("  -h \t\tPrint this message")
		fmt.Println("  -testnet \tGenerate a testnet key instead of mainnet")
	}

	setupFlags(helpMessage, flag.CommandLine)
	flag.Parse()

	if flag.Arg(0) == "" {
		helpMessage()
		return
	}

	// Alter the globals to testnet.
	if *testnet != false {
		PrivateKeyID = PrivateKeyIDTest
		PubKeyHashAddrID = PubKeyHashAddrIDTest
	}

	generateKeyPair(flag.Arg(0))
	fmt.Printf("Successfully generated keypair and stored it in %v.\n",
		flag.Arg(0))
	fmt.Printf("Your private key is used to spend your funds. Do not " +
		"reveal it to anyone.\n")
}
