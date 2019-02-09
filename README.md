dcraddrgen
====

[![Build Status](https://travis-ci.org/decred/dcraddrgen.png?branch=master)](https://travis-ci.org/decred/dcraddrgen)
[![GoDoc](https://godoc.org/github.com/decred/dcraddrgen?status.png)](http://godoc.org/github.com/decred/dcraddrgen)


dcraddrgen is a simple offline address generator for [decred](https://decred.org/).

It allows one to generate an address (along with either the private
key or a wallet seed) without a running wallet or daemon.

## Installation and updating

### Windows/Linux/BSD/POSIX - Build from source

Building or updating from source requires the following build dependencies:

- **Go 1.11**

  Installation instructions can be found here: http://golang.org/doc/install.
  It is recommended to add `$GOPATH/bin` to your `PATH` at this point.

**Getting the source**:

For a first time installation, the project and dependency sources can be
obtained manually with `git` and `dep` (create directories as needed):

```
git clone https://github.com/decred/dcraddrgen $GOPATH/src/github.com/decred/dcraddrgen
cd $GOPATH/src/github.com/decred/dcraddrgen
```

To update an existing source tree, pull the latest changes and install the
matching dependencies:

```
cd $GOPATH/src/github.com/decred/dcraddrgen
git pull
```

**Building/Installing**:

The `go` tool is used to build or install (to `GOPATH`) the project.  Some
example build instructions are provided below (all must run from the `dcraddrgen`
project directory).

To build a `dcraddrgen` executable and install it to `$GOPATH/bin/`:

```
go install
```

To build a `dcraddrgen` executable and place it in the current directory:

```
go build
```

## Usage

```
Usage: dcraddrgen [-testnet] [-simnet] [-regtest] [-noseed] [-nofile] [-h] filename
Generate a Decred private and public key or wallet seed.
These are output to the file 'filename'.

  -h          Print this message
  -testnet    Generate a testnet key instead of mainnet
  -simnet     Generate a simnet key instead of mainnet
  -regtest    Generate a regtest key instead of mainnet
  -noseed     Generate a single keypair instead of a seed
  -nofile     Write the key pair in stdout, not in 'filename'
  -verify     Verify a seed by generating the first address
```
