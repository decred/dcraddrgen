dcraddrgen
====

[![Build Status](https://travis-ci.org/decred/dcraddrgen.png?branch=master)]
(https://travis-ci.org/decred/dcraddrgen)
[![GoDoc](https://godoc.org/github.com/decred/dcraddrgen?status.png)]
(http://godoc.org/github.com/decred/dcraddrgen)


dcraddrgen is a simple offline address generator for [decred](https://decred.org/).

It allows one to generate an address (along with either the private
key or a wallet seed) without a running wallet or daemon.

## Requirements

[Go](http://golang.org) 1.5 or newer.

## Installation

```bash
$ go get -u github.com/decred/dcraddrgen
```

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
