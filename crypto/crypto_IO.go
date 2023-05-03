package crypto

import (
	"CTngV2/util"
	"crypto/rsa"
	"encoding/json"
	"fmt"
)

type CryptoStorage interface {
	GenerateCryptoCryptoConfigs([]CTngID, int) error
	SaveCryptoFiles(string, []CryptoConfig) error
	ReadCryptoConfig(file string) (*CryptoConfig, error)
}

// Generate a list of cryptoconfigs from a list of entity names.
// The threshold determines the k value in "k-of-n" threshold signing.
func GenerateEntityCryptoConfigs(entityIDs []CTngID, threshold int) ([]CryptoConfig, error) {
	ThresholdScheme := "bls"
	SignScheme := "rsa"
	HashScheme := SHA256
	configs := make([]CryptoConfig, len(entityIDs))

	// Generate Threshold Keys
	_, blsPubMap, blsPrivMap, err := GenerateThresholdKeypairs(entityIDs, threshold)
	if err != nil {
		panic(err)
	}

	// Map entity identifiers to given BLS IDs

	// Generate RSA Keys
	rsaPrivMap := make(map[CTngID]rsa.PrivateKey)
	rsaPubMap := make(RSAPublicMap)
	for _, entity := range entityIDs {
		priv, err := NewRSAPrivateKey()
		if err != nil {
			panic(err)
		}
		pub := priv.PublicKey
		rsaPrivMap[entity] = *priv
		rsaPubMap[entity] = pub
	}

	//Generate configs without individual information
	for i := range configs {
		configs[i] = CryptoConfig{
			ThresholdScheme:    ThresholdScheme,
			SignScheme:         SignScheme,
			HashScheme:         HashScheme,
			Threshold:          threshold,
			N:                  len(entityIDs),
			SelfID:             entityIDs[i],
			SignPublicMap:      rsaPubMap,
			SignSecretKey:      rsaPrivMap[entityIDs[i]],
			ThresholdPublicMap: blsPubMap,
			ThresholdSecretKey: blsPrivMap[entityIDs[i]],
		}
	}
	return configs, nil
}

// Saves a list of cryptoconfigs to files in a directory.
// Each file is named the ID of the corresponding entity.
func SaveCryptoFiles(directory string, configs []CryptoConfig) error {
	// check if directory exists, if not create it
	util.CreateDir(directory)
	for _, config := range configs {
		// fmt.Print(config)
		file := fmt.Sprintf("%s/%s.test.json", directory, config.SelfID)
		err := util.WriteData(file, *NewStoredCryptoConfig(&config))
		if err != nil {
			return err
		}
	}
	return nil
}

// Read a storedcryptoconfig from a file, convert it to a cryptoconfig and return a pointer to it.
func ReadCryptoConfig(file string) (*CryptoConfig, error) {
	scc := new(StoredCryptoConfig)
	bytes, err := util.ReadByte(file)
	json.Unmarshal(bytes, scc)
	if err != nil {
		return nil, err
	}
	cc, err := NewCryptoConfig(scc)
	return cc, err
}

// Read a stored basic crypto config from a file, convert it to a basiccryptoconfig and return a pointer to it.
func ReadBasicCryptoConfig(file string) (*CryptoConfig, error) {
	scc := new(StoredCryptoConfig)
	bytes, err := util.ReadByte(file)
	json.Unmarshal(bytes, scc)
	if err != nil {
		return nil, err
	}
	cc, err := NewBasicCryptoConfig(scc)
	return cc, err
}

// Converts a CryptoConfig to a marshal-able format.
func NewStoredCryptoConfig(c *CryptoConfig) *StoredCryptoConfig {
	scc := new(StoredCryptoConfig)
	scc = &StoredCryptoConfig{
		Threshold:       c.Threshold,
		N:               c.N,
		SignScheme:      c.SignScheme,
		ThresholdScheme: c.ThresholdScheme,
		HashScheme:      int(c.HashScheme),
		SelfID:          c.SelfID,
		SignPublicMap:   c.SignPublicMap,
		SignSecretKey:   c.SignSecretKey,
	}
	scc.ThresholdPublicMap = (&c.ThresholdPublicMap).Serialize()
	scc.ThresholdSecretKey = (&c.ThresholdSecretKey).Serialize()
	return scc
}

// Creates a cryptoconfig from a stored one. This is used for reading a stored file cryptoconfig.
// Returns a pointer to the new config.
func NewCryptoConfig(scc *StoredCryptoConfig) (*CryptoConfig, error) {
	c := new(CryptoConfig)
	c = &CryptoConfig{
		Threshold:          scc.Threshold,
		N:                  scc.N,
		SignScheme:         scc.SignScheme,
		ThresholdScheme:    scc.ThresholdScheme,
		HashScheme:         HashAlgorithm(scc.HashScheme),
		SelfID:             scc.SelfID,
		SignSecretKey:      scc.SignSecretKey,
		SignPublicMap:      scc.SignPublicMap,
		ThresholdPublicMap: make(BlsPublicMap),
	}
	err := (&c.ThresholdPublicMap).Deserialize(scc.ThresholdPublicMap)
	if err != nil {
		return c, err
	}
	err = (&c.ThresholdSecretKey).Deserialize(scc.ThresholdSecretKey)
	if err != nil {
		return c, err
	}
	return c, nil
}

// Creates a cryptoconfig from a stored one. This is used for reading a stored file cryptoconfig.
// Returns a pointer to the new config.
func NewBasicCryptoConfig(scc *StoredCryptoConfig) (*CryptoConfig, error) {
	c := new(CryptoConfig)
	c = &CryptoConfig{
		Threshold:          0,
		N:                  0,
		SignScheme:         scc.SignScheme,
		ThresholdScheme:    "",
		HashScheme:         HashAlgorithm(scc.HashScheme),
		SelfID:             scc.SelfID,
		SignSecretKey:      scc.SignSecretKey,
		SignPublicMap:      scc.SignPublicMap,
		ThresholdPublicMap: nil,
	}
	return c, nil
}
