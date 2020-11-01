dcraddrgen
==========

[![Build Status](https://github.com/decred/dcraddrgen/workflows/Build%20and%20Test/badge.svg)](https://github.com/decred/dcraddrgen/actions)
[![ISC License](https://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)
[![Doc](https://img.shields.io/badge/doc-reference-blue.svg)](https://pkg.go.dev/github.com/decred/dcraddrgen)

dcraddrgen is a simple offline address generator for [decred](https://decred.org/).

It allows one to generate an address (along with either the private
key or a wallet seed) without a running wallet or daemon.

## Usage

```
Usage: dcraddrgen [-testnet] [-simnet] [-regtest] [-noseed] [-h] filename
Generate a Decred private and public key or wallet seed.
These are output to the file 'filename'.

  -h 		    Print this message
  -testnet 	    Generate a testnet key instead of mainnet
  -simnet       Generate a simnet key instead of mainnet
  -regtest      Generate a regtest key instead of mainnet
  -noseed       Generate a single keypair instead of a seed
  -verify 	    Verify a seed by generating the first address
```
