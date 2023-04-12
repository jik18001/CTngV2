# Package Logger
## types.go
This file contains the data types and functions used by the Logger package. The data types include:

- `Logger_public_config`: A struct that holds the public configuration data for a Logger.
- `Logger_private_config`: A struct that holds the private configuration data for a Logger.
- `LoggerContext`: A struct that represents the context of a Logger. It includes various fields such as a HTTP client, public and private configuration data, cryptographic configurations, and more.
- `PrecertStorage`: A struct that holds the certificate pool data.
- `Verifyprecert`: Verifies a precert using the public key of the issuer.
- `InitializeLoggerContext`: Initializes the context for a Logger.
- `GenerateLogger_private_config_template`: Generates a private configuration template for a Logger.
- `GenerateLogger_public_config_template`: Generates a public configuration template for a Logger.
- `GenerateLogger_crypto_config_template`: Generates a cryptographic configuration template for a Logger.


## merkle_tree.go
This file defines functions for building and working with Merkle trees. The Merkle tree is a fundamental data structure in Certificate Transparency (CT) that enables efficient verification of certificate inclusion in the CT log.

The functions in this file include:

- `doubleHash`: Computes the double hash of two byte arrays and returns the result.
- `VerifyPOI`: Verifies the proof of inclusion (POI) of a certificate in the CT log by computing the hash chain and comparing it to the root hash in the Signed Tree Head (STH).
- `BuildMerkleTreeFromCerts`: Builds a Merkle tree from an array of certificates and returns the corresponding STH, leaf nodes, and POIs.
- `addPOI`: Adds the POI to a node in the Merkle tree and recursively adds POIs to its children.
- `hash`: Computes the SHA256 hash of a byte array and returns the result.
- `addPOIAndSTH`: Adds the POI and STH to a node in the Merkle tree and recursively adds POIs and STHs to its children.
- `generateMerkleTree`: Generates a Merkle tree from an array of leaf nodes and returns the root node and leaf nodes.

## server.go

- `bindLoggerContext`: This function binds a Logger context to a handler function, returning the bound function.
- `handleLoggerRequests`:This function sets up the HTTP server for the logger and handles incoming requests.
- `requestSTH`:This function returns the Signed Tree Head (STH) for the current period.
- `receive_pre_cert`: This function receives Precertificates from a Certificate Authority (CA) and adds them to the current precert pool.
- `Send_STH_to_CA`: This function sends the STH to the specified CA.
- `Send_POI_to_CA`:This function sends a single POI to the specified CA.
- `Send_POIs_to_CAs`: This function sends all POIs for the current period to their respective Issuer CAs.
- `GetCurrentPeriod`: This function returns the current period.
- `GerCurrentSecond`:This function returns the current second.
- `PeriodicTask`:This function performs the periodic tasks of the logger, including computing the STH and POIs, updating the STH storage, and sending the STH and POIs to the appropriate CAs.
- `StartLogger`: This function starts the logger by setting up the HTTP server and running the periodic task.

## logger_test.go
- `TestMerkleTree`: a test for the Merkle tree implementation.


