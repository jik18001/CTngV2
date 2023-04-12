# Cryptography Implementations

## Contents: 
- `types.go`: type declarations with descriptions for all the files below.
- `bls.go`: implementation of k-of-n threshold signatures using a BLS library.
- `rsa.go`: Creates slightly simplified+application specific RSA functions from go's "crypto/rsa" library.
- `hash.go`: functions for hashing of data using a variety of schemes.
- `generate_crypto.go`:  Given security constraints/requirements and the names of each entity in the network, generate BLS and RSA keys, and create and store CryptoConfig files for each entity.

## crypto_config.go:
- `CryptoConfig` is an object that contains all the cryptographic information for an entity to use
  - e.x: Mappings to public keys, Private keys, signature schemes being utilized, etc.
- For convenience, methods are defined for this object which use the information stored within the config to Hash, Sign, and Verify signatures.
- Thus, all cryptographic actions are condensed to a single object.

## Signature Object Format:
- `RSASig`, `ThresholdSig`, and `SigFragment` are objects of signatures bundled with the signing entity. (BLS for the latter two).
- While this information is typically contained within a gossip object's Signer Field, there currently isn't a way to store multiple signers of data in a gossip object. Thus, this implementation is integral to the `ThresholdSig` Type. 

## cyrpto_test.go
The following tests are included:
1. Hash function test
2. K-of-n BLS key generation + signing/verifying with different subsets
3. IO function tests: Writes and then reads a cryptoconfig and verifies functionality
