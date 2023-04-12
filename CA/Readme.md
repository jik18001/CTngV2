# Package CA 

## types.go

This file defines various data types and functions used by the CA package. The data types include:

- `CAContext`: A struct that represents the context of a Certificate Authority (CA). It includes various fields such as a HTTP client, public and private configuration data, cryptographic configurations, and more.
- `CA_public_config`: A struct that holds the public configuration data for a CA.
- `CA_private_config`: A struct that holds the private configuration data for a CA.
- `ProofOfInclusion`: A struct that represents the proof of inclusion of a certificate in the Certificate Transparency (CT) log.
- `POI`: A struct that holds the `ProofOfInclusion` and other relevant data.
- `CTngExtension`: A struct that holds the STH (Signed Tree Head) and POI (Proof of Inclusion) for a certificate.
- `SequenceNumber`: A struct that holds the sequence number of a certificate.
- `CTngCertPoolStorage`: A struct that holds the certificate pool data.
- `any`: A type that represents any value.

The functions in this file include:

- `AddCTngExtension`: Adds a CTngExtension to a certificate.
- `GetCTngExtensions`: Gets all CTngExtensions from a certificate.
- `GetSequenceNumberfromCert`: Gets the sequence number from a certificate.
- `GetLoggerInfofromCert`: Gets the logger information from a certificate.
- `GetCTngExtensionCount`: Gets the number of CTngExtensions in a certificate.
- `GetPrecertfromCert`: Gets the precert from a certificate.
- `GenerateCA_public_config_template`: Generates a public configuration template for a CA.
- `GenerateCA_Crypto_config_template`: Generates a cryptographic configuration template for a CA.
- `GenerateCA_private_config_template`: Generates a private configuration template for a CA.
- `publicKey`: Generates a public key from a private key.
- `GenerateRSAKeyPair`: Generates an RSA key pair.
- `WriteConfigToFile`: Writes a configuration to a file.
- `SaveToStorage`: Saves a certificate pool to storage.
- `InitializeCAContext`: Initializes the context for a CA.

## cert_pool.go

This file contains the implementation of a certificate pool used in the CA package. The `CertPool` struct is a set of certificates that allows for efficient searches and addition of new certificates. The file includes functions for finding potential parents of a given certificate, adding a certificate to the pool, appending certificates from PEM-encoded data, and getting a certificate from the pool by its subject key ID.

The functions in this file include:

- `NewCertPool`: Creates a new, empty `CertPool`.
- `copy`: Creates a copy of a `CertPool`.
- `findPotentialParents`: Returns the indexes of certificates in a `CertPool` that might have signed a given certificate.
- `contains`: Checks if a given certificate is already in a `CertPool`.
- `AddCert`: Adds a certificate to a `CertPool`.
- `AppendCertsFromPEM`: Attempts to parse a series of PEM-encoded certificates and appends any certificates found to a `CertPool`.
- `Subjects`: Returns a list of the DER-encoded subjects of all certificates in a `CertPool`.
- `GetCertBySubjectKeyID`: Gets a certificate from a `CertPool` by its subject key ID.
- `GetLength`: Gets the number of certificates in a `CertPool`.
- `GetCertList`: Gets a list of certificates in a `CertPool`.
- `GetCerts`: Gets an array of certificates in a `CertPool`.
- `UpdateCertBySubjectID`:Updates a certificate in a CertPool by its subject key ID.

## crv.go

This file defines the `CRV` (Certificate Revocation Vector) and `Revocation` data types and their associated functions used by the `CA` package.

### CRV data type

The `CRV` data type includes:

- `CRV_pre_update`: A bitset representing the CRV prior to the update.
- `CRV_current`: A bitset representing the current CRV.
- `CRV_cache`: A map of string to a bitset representing a cached CRV.

The functions in this file include:

- `CRV_init()`: Initializes a new `CRV` struct with empty bitsets and a cache.
- `GetDeltaCRV()`: Computes the delta between the `CRV_pre_update` and `CRV_current` bitsets.
- `GetDeltaCRVCache()`: Computes the delta between one of the cached `CRV` and `CRV_current` bitsets.
- `Revoke()`: Sets a bit in the `CRV_current` bitset to revoke a certificate.

### Revocation data type

The `Revocation` data type includes:

- `Period`: A string representing the time period of the revocation.
- `Delta_CRV`: A byte slice representing the delta between the `CRV_pre_update` and `CRV_current` bitsets.
- `SRH`: A string representing the signed hash of the revocation data.

The functions in this file include:

- `Generate_Revocation()`: Generates a revocation object with the given time period and type. It computes the delta between the `CRV_pre_update` and `CRV_current` bitsets and hashes the resulting data along with the time period to create a revocation hash. The revocation hash is then signed using the CA's private key and returned in a gossip object.



## ca.go

This file contains several functions related to X.509 certificate generation and signing.

- `Generate_Unsigned_PreCert()`: Generates an unsigned X.509 pre-certificate with specified parameters like subject, issuer, host, and validFor.
- `Sign_certificate()`: Signs a given X.509 certificate with a root certificate using RSA public and private keys.
- `Generate_Root_Certificate()`: Generates a self-signed root X.509 certificate.
- `Generate_Signed_PreCert()`: Generates and signs an X.509 pre-certificate with specified parameters like subject, issuer, host, and validFor.
- `Generate_Selfsigned_root_cert()`: Generates and signs a self-signed X.509 root certificate.
- `Generate_N_Subjects()`: Generates N number of X.509 subject names with a common name of "Testing Dummy" and a unique number appended to it.
- `Generate_N_KeyPairs()`: Generates N number of RSA public/private key pairs and returns a map of the public keys with subject names as keys.
- `Generate_and_return_N_KeyPairs()`: Generates N number of RSA public/private key pairs and returns two maps, one for public keys and another for private keys.
- `Generate_Issuer()`: Generates an X.509 issuer with the specified name.
- `Generate_N_Signed_PreCert()`: Generates and signs N number of X.509 pre-certificates with different subjects.
- `Generate_N_Signed_PreCert_with_priv()`: Generates and signs N number of X.509 pre-certificates with different subjects and returns the private keys for each certificate.
- `Marshall_Signed_PreCert()`: Marshals an X.509 certificate to JSON.
- `Unmarshall_Signed_PreCert()`: Unmarshals a JSON representation of an X.509 certificate to an X.509 certificate object.


## server.go

This file contains several functions related to handling HTTP requests and tasks for the CA server.

- `handleCARequests(c *CAContext)`: This function sets up a Gorilla Mux router to route HTTP requests to the appropriate handlers. The handlers for this CA include receiving STH, receiving POI, and getting revocation data.
- `requestREV(c *CAContext, w http.ResponseWriter, r *http.Request)`: This function handles the GET request for revocation data from a monitor.
- `receive_sth(c *CAContext, w http.ResponseWriter, r *http.Request)`: This function receives an STH object from a logger and verifies it before storing it.
- `receive_poi(c *CAContext, w http.ResponseWriter, r *http.Request)`: This function receives a POI object from a logger and verifies it before updating the CTngExtension field in a certificate.
- `Send_Signed_PreCert_To_Logger(c *CAContext, precert *x509.Certificate, logger string)`: This function sends a signed pre-certificate to a specified logger.
- `SignAllCerts(c *CAContext) []x509.Certificate`: This function signs all certificates in the CA's certificate pool.
- `PeriodicTask(ctx *CAContext)`: This function performs periodic tasks such as wiping the STH storage, generating and sending pre-certificates to loggers, generating and storing revocation data, and saving the CA's context to storage.

## ca_test.go

This file contains several test functions for the CA package.

- `testCRV(t *testing.T)`: Tests the functionality of the CRV data type.
- `TestCAContext(t *testing.T)`: Tests the functionality of the CA context.
- `testCertMarshal(t *testing.T)`: Tests marshalling and unmarshalling of X.509 certificates.
- `testPOIjson(t *testing.T)`: Tests marshalling and unmarshalling of POI objects.
- `testCtngExtension(t *testing.T)`: Tests the functionality of CTng extensions.


