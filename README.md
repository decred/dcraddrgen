dcraddrgen
====

dcraddrgen is a simple offline address generator for decred.

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
Usage: dcraddrgen [-testnet] [-h] filename
Generate a Decred private and public key. These are output to the file 'filename'.

  -h 		Print this message
  -testnet 	Generate a testnet key instead of mainnet
```
