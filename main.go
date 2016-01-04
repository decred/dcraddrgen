// Copyright (c) 2015 The Decred Developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/btcsuite/btcd/btcec"
	"github.com/decred/dcraddrgen/address"
	"github.com/decred/dcraddrgen/hdkeychain"
	"github.com/decred/dcraddrgen/pgpwordlist"
)

// The hierarchy described by BIP0043 is:
//  m/<purpose>'/*
// This is further extended by BIP0044 to:
//  m/44'/<coin type>'/<account>'/<branch>/<address index>
//
// The branch is 0 for external addresses and 1 for internal addresses.

// maxCoinType is the maximum allowed coin type used when structuring
// the BIP0044 multi-account hierarchy.  This value is based on the
// limitation of the underlying hierarchical deterministic key
// derivation.
const maxCoinType = hdkeychain.HardenedKeyStart - 1

// MaxAccountNum is the maximum allowed account number.  This value was
// chosen because accounts are hardened children and therefore must
// not exceed the hardened child range of extended keys and it provides
// a reserved account at the top of the range for supporting imported
// addresses.
const MaxAccountNum = hdkeychain.HardenedKeyStart - 2 // 2^31 - 2

// ExternalBranch is the child number to use when performing BIP0044
// style hierarchical deterministic key derivation for the external
// branch.
const ExternalBranch uint32 = 0

// InternalBranch is the child number to use when performing BIP0044
// style hierarchical deterministic key derivation for the internal
// branch.
const InternalBranch uint32 = 1

// Magics.

// MainHDPrivateKeyID is the hd private key id for mainnet.
// starts with dprv
var MainHDPrivateKeyID = [4]byte{0x02, 0xfd, 0xa4, 0xe8}

// MainHDPublicKeyID is the hd public key id for mainnet.
// starts with dpub
var MainHDPublicKeyID = [4]byte{0x02, 0xfd, 0xa9, 0x26}

// PubKeyHashAddrIDMain is the public key hash address id for mainnet.
var PubKeyHashAddrIDMain = [2]byte{0x07, 0x3f}

// MainHDCoinType is the cointype for mainnet.
var MainHDCoinType = uint32(20)

// TestHDPrivateKeyID is the hd private key id for testnet.
// starts with tprv
var TestHDPrivateKeyID = [4]byte{0x04, 0x35, 0x83, 0x97}

// TestHDPublicKeyID is the hd public key id for testnet.
// starts with tpub
var TestHDPublicKeyID = [4]byte{0x04, 0x35, 0x87, 0xd1}

// PubKeyHashAddrIDTest is the public key hash address id for testnet.
var PubKeyHashAddrIDTest = [2]byte{0x0f, 0x21}

// TestHDCoinType is the cointype for testnet.
var TestHDCoinType = uint32(11)

// SimHDPrivateKeyID is the hd private key id for simnet.
// starts with sprv
var SimHDPrivateKeyID = [4]byte{0x04, 0x20, 0xb9, 0x03}

// SimHDPublicKeyID is the hd public key id for testnet.
// starts with spub
var SimHDPublicKeyID = [4]byte{0x04, 0x20, 0xbd, 0x3d}

// PubKeyHashAddrIDSim is the public key hash address id for simnet.
var PubKeyHashAddrIDSim = [2]byte{0x0e, 0x91}

// SimHDCoinType is the cointype for simnet.
var SimHDCoinType = uint32(115)

// RegHDPrivateKeyID is the hd private key id for regtest.
// starts with Tprv
var RegHDPrivateKeyID = [4]byte{0x02, 0x2d, 0xbb, 0x24}

// RegHDPublicKeyID is the hd public key id for regtest.
// starts with Tpub
var RegHDPublicKeyID = [4]byte{0x02, 0x2d, 0xbf, 0x5d}

// PubKeyHashAddrIDReg is the public key hash address id for regtest.
var PubKeyHashAddrIDReg = [2]byte{0x0e, 0x01}

// RegHDCoinType is the cointype for regtest.
var RegHDCoinType = uint32(10)

var curve = btcec.S256()
var privateKeyID = PrivateKeyIDMain
var pubKeyHashAddrID = PubKeyHashAddrIDMain
var hdPrivateKeyID = MainHDPrivateKeyID
var hdPublicKeyID = MainHDPublicKeyID
var hdCoinType = MainHDCoinType

// Flag arguments.
var testnet = flag.Bool("testnet", false, "")
var simnet = flag.Bool("simnet", false, "")
var regtest = flag.Bool("regtest", false, "")
var noseed = flag.Bool("noseed", false, "Generate a single keypair instead of "+
	"an HD extended seed")

func setupFlags(msg func(), f *flag.FlagSet) {
	f.Usage = msg
}

// writeNewFile writes data to a file named by filename.
// Error is returned if the file does exist. Otherwise writeNewFile creates the file with permissions perm;
// Based on ioutil.WriteFile, but produces an err if the file exists.
func writeNewFile(filename string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	n, err := f.Write(data)
	if err == nil && n < len(data) {
		// There was no error, but not all the data was written, so report an error.
		err = io.ErrShortWrite
	}
	if err == nil {
		// There was an error, so close file (ignoreing any further errors) and return the error.
		f.Close()
		return err
	}
	err = f.Close()
	if err != nil {
		return err
	}
	return nil
}

// generateKeyPair generates and stores a secp256k1 keypair in a file.
func generateKeyPair(filename string) error {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return err
	}
	pub := btcec.PublicKey{
		Curve: curve,
		X:     key.PublicKey.X,
		Y:     key.PublicKey.Y,
	}
	priv := btcec.PrivateKey{
		PublicKey: key.PublicKey,
		D:         key.D,
	}

	addr, err := address.NewAddressPubKeyHash(Hash160(pub.SerializeCompressed()),
		pubKeyHashAddrID)
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

	err = writeNewFile(filename, buf.Bytes(), 0644)
	if err != nil {
		return err
	}
	return nil
}

// deriveCoinTypeKey derives the cointype key which can be used to derive the
// extended key for an account according to the hierarchy described by BIP0044
// given the coin type key.
//
// In particular this is the hierarchical deterministic extended key path:
// m/44'/<coin type>'
func deriveCoinTypeKey(masterNode *hdkeychain.ExtendedKey,
	coinType uint32) (*hdkeychain.ExtendedKey, error) {
	// Enforce maximum coin type.
	if coinType > maxCoinType {
		return nil, fmt.Errorf("bad coin type")
	}

	// The hierarchy described by BIP0043 is:
	//  m/<purpose>'/*
	// This is further extended by BIP0044 to:
	//  m/44'/<coin type>'/<account>'/<branch>/<address index>
	//
	// The branch is 0 for external addresses and 1 for internal addresses.

	// Derive the purpose key as a child of the master node.
	purpose, err := masterNode.Child(44 + hdkeychain.HardenedKeyStart)
	if err != nil {
		return nil, err
	}

	// Derive the coin type key as a child of the purpose key.
	coinTypeKey, err := purpose.Child(coinType + hdkeychain.HardenedKeyStart)
	if err != nil {
		return nil, err
	}

	return coinTypeKey, nil
}

// deriveAccountKey derives the extended key for an account according to the
// hierarchy described by BIP0044 given the master node.
//
// In particular this is the hierarchical deterministic extended key path:
//   m/44'/<coin type>'/<account>'
func deriveAccountKey(coinTypeKey *hdkeychain.ExtendedKey,
	account uint32) (*hdkeychain.ExtendedKey, error) {
	// Enforce maximum account number.
	if account > MaxAccountNum {
		return nil, fmt.Errorf("account num too high")
	}

	// Derive the account key as a child of the coin type key.
	return coinTypeKey.Child(account + hdkeychain.HardenedKeyStart)
}

// checkBranchKeys ensures deriving the extended keys for the internal and
// external branches given an account key does not result in an invalid child
// error which means the chosen seed is not usable.  This conforms to the
// hierarchy described by BIP0044 so long as the account key is already derived
// accordingly.
//
// In particular this is the hierarchical deterministic extended key path:
//   m/44'/<coin type>'/<account>'/<branch>
//
// The branch is 0 for external addresses and 1 for internal addresses.
func checkBranchKeys(acctKey *hdkeychain.ExtendedKey) error {
	// Derive the external branch as the first child of the account key.
	if _, err := acctKey.Child(ExternalBranch); err != nil {
		return err
	}

	// Derive the external branch as the second child of the account key.
	_, err := acctKey.Child(InternalBranch)
	return err
}

// generateSeed derives an address from an HDKeychain for use in wallet. It
// outputs the seed, address, and extended public key to the file specified.
func generateSeed(filename string) error {
	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	if err != nil {
		return err
	}

	// Derive the master extended key from the seed.
	root, err := hdkeychain.NewMaster(seed, hdPrivateKeyID)
	if err != nil {
		return err
	}

	// Derive the cointype key according to BIP0044.
	coinTypeKeyPriv, err := deriveCoinTypeKey(root, hdCoinType)
	if err != nil {
		return err
	}

	// Derive the account key for the first account according to BIP0044.
	acctKeyPriv, err := deriveAccountKey(coinTypeKeyPriv, 0)
	if err != nil {
		// The seed is unusable if the any of the children in the
		// required hierarchy can't be derived due to invalid child.
		if err == hdkeychain.ErrInvalidChild {
			return fmt.Errorf("the provided seed is unusable")
		}

		return err
	}

	// Ensure the branch keys can be derived for the provided seed according
	// to BIP0044.
	if err := checkBranchKeys(acctKeyPriv); err != nil {
		// The seed is unusable if the any of the children in the
		// required hierarchy can't be derived due to invalid child.
		if err == hdkeychain.ErrInvalidChild {
			return fmt.Errorf("the provided seed is unusable")
		}

		return err
	}

	// The address manager needs the public extended key for the account.
	acctKeyPub, err := acctKeyPriv.Neuter()
	if err != nil {
		return fmt.Errorf("failed to convert private key for account 0")
	}

	index := uint32(0)  // First address
	branch := uint32(0) // External

	// The next address can only be generated for accounts that have already
	// been created.
	acctKey := acctKeyPub

	// Derive the appropriate branch key and ensure it is zeroed when done.
	branchKey, err := acctKey.Child(branch)
	if err != nil {
		return err
	}
	defer branchKey.Zero() // Ensure branch key is zeroed when done.

	key, err := branchKey.Child(index)
	if err != nil {
		return err
	}

	addr, err := key.Address(pubKeyHashAddrID)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	buf.WriteString("First address: ")
	buf.WriteString(addr.EncodeAddress())
	buf.WriteString("\n")
	buf.WriteString("Extended public key: ")
	acctKeyStr, err := acctKey.String()
	if err != nil {
		return err
	}
	buf.WriteString(acctKeyStr)
	buf.WriteString("\n")
	buf.WriteString("Seed: ")
	seedStr, err := pgpwordlist.ToStringChecksum(seed)
	if err != nil {
		return err
	}
	buf.WriteString(seedStr)
	buf.WriteString("\n")
	buf.WriteString("Seed hex: ")
	buf.WriteString(fmt.Sprintf("%x", seed))
	buf.WriteString("\n")

	err = writeNewFile(filename, buf.Bytes(), 0644)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	helpMessage := func() {
		fmt.Println("Usage: dcraddrgen [-testnet] [-simnet] [-regtest] [-noseed] [-h] filename")
		fmt.Println("Generate a Decred private and public key or wallet seed.  " +
			"These are output to the file 'filename'.\n")
		fmt.Println("  -h \t\tPrint this message")
		fmt.Println("  -testnet \tGenerate a testnet key instead of mainnet")
		fmt.Println("  -simnet \tGenerate a simnet key instead of mainnet")
		fmt.Println("  -regtest \tGenerate a regtest key instead of mainnet")
		fmt.Println("  -noseed \tGenerate a single keypair instead of a seed")
	}

	setupFlags(helpMessage, flag.CommandLine)
	flag.Parse()

	if flag.Arg(0) == "" {
		helpMessage()
		return
	}

	// Alter the globals to specified network.
	if *testnet {
		if *simnet || *regtest {
			fmt.Println("Error: Only specify one network.")
			return
		}
		privateKeyID = PrivateKeyIDTest
		pubKeyHashAddrID = PubKeyHashAddrIDTest
		hdPrivateKeyID = TestHDPrivateKeyID
		hdPublicKeyID = TestHDPublicKeyID
		hdCoinType = TestHDCoinType
	}
	if *simnet {
		if *regtest {
			fmt.Println("Error: Only specify one network.")
			return
		}
		privateKeyID = PrivateKeyIDSim
		pubKeyHashAddrID = PubKeyHashAddrIDSim
		hdPrivateKeyID = SimHDPrivateKeyID
		hdPublicKeyID = SimHDPublicKeyID
		hdCoinType = SimHDCoinType
	}
	if *regtest {
		privateKeyID = PrivateKeyIDReg
		pubKeyHashAddrID = PubKeyHashAddrIDReg
		hdPrivateKeyID = RegHDPrivateKeyID
		hdPublicKeyID = RegHDPublicKeyID
		hdCoinType = RegHDCoinType
	}

	// Single keypair generation.
	if *noseed {
		err := generateKeyPair(flag.Arg(0))
		if err != nil {
			fmt.Printf("Error generating key pair: %v\n", err.Error())
			return
		}
		fmt.Printf("Successfully generated keypair and stored it in %v.\n",
			flag.Arg(0))
		fmt.Printf("Your private key is used to spend your funds. Do not " +
			"reveal it to anyone.\n")
		return
	}

	// Derivation of an address from an HDKeychain for use in wallet.
	err := generateSeed(flag.Arg(0))
	if err != nil {
		fmt.Printf("Error generating seed: %v\n", err.Error())
		return
	}
	fmt.Printf("Successfully generated seed and stored it in %v.\n",
		flag.Arg(0))
	fmt.Printf("Your seed is used to spend your funds. Do not " +
		"reveal it to anyone. Your extended public key can be " +
		"used to derive all your addresses. Keep it private.\n")
}
