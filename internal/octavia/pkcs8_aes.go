/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package octavia

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

var (
	// key derivation functions
	oidPKCS5PBKDF2    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidPBES2          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}

	// encryption
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// Encrypted pkcs8
// Based on https://github.com/youmark/pkcs8
// MIT license
type prfParam struct {
	Algo      asn1.ObjectIdentifier
	NullParam asn1.RawValue
}

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	PrfParam       prfParam `asn1:"optional"`
}

type pbkdf2Algorithms struct {
	Algo         asn1.ObjectIdentifier
	PBKDF2Params pbkdf2Params
}

type pbkdf2Encs struct {
	EncryAlgo asn1.ObjectIdentifier
	IV        []byte
}

type pbes2Params struct {
	KeyDerivationFunc pbkdf2Algorithms
	EncryptionScheme  pbkdf2Encs
}

type encryptedlAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters pbes2Params
}

type encryptedPrivateKeyInfo struct {
	Algo       encryptedlAlgorithmIdentifier
	PrivateKey []byte
}

// EncryptPrivateKey encrypts given private key data using AES in PKCS#8 format
func EncryptPrivateKey(data, password []byte) (*pem.Block, error) {
	pbkdf2Iterations := 600000
	aes256Keysize := 32
	dataLength := len(data)
	padSize := aes.BlockSize - dataLength%aes.BlockSize
	encryptedSize := dataLength + padSize

	// Generate salt using random data
	pbkdf2Salt := make([]byte, 16)
	_, err := rand.Read(pbkdf2Salt)
	if err != nil {
		err = fmt.Errorf("error generating random data for salt for private key encryption: %w", err)
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		err = fmt.Errorf("error generating random data for init vector for private key encryption: %w", err)
		return nil, err
	}

	key := pbkdf2.Key(password, pbkdf2Salt, pbkdf2Iterations,
		aes256Keysize, sha256.New)
	encryptedBlock, err := aes.NewCipher(key)
	if err != nil {
		err = fmt.Errorf("error creating new cipher block for private key encryption: %w", err)
		return nil, err
	}

	cryptSource := make([]byte, encryptedSize)
	copy(cryptSource, data)
	// Set padding data according to RFC1423, 1.1
	for i := dataLength; i < encryptedSize; i++ {
		cryptSource[i] = byte(padSize)
	}
	encrypted := make([]byte, encryptedSize)

	encrypter := cipher.NewCBCEncrypter(encryptedBlock, iv)
	encrypter.CryptBlocks(encrypted, cryptSource)

	// Build encrypted ans1 data
	pki := encryptedPrivateKeyInfo{
		Algo: encryptedlAlgorithmIdentifier{
			Algorithm: oidPBES2,
			Parameters: pbes2Params{
				KeyDerivationFunc: pbkdf2Algorithms{
					Algo: oidPKCS5PBKDF2,
					PBKDF2Params: pbkdf2Params{
						Salt:           pbkdf2Salt,
						IterationCount: pbkdf2Iterations,
						PrfParam: prfParam{
							Algo:      oidHMACWithSHA256,
							NullParam: asn1.NullRawValue,
						},
					},
				},
				EncryptionScheme: pbkdf2Encs{
					EncryAlgo: oidAES256CBC,
					IV:        iv,
				},
			},
		},
		PrivateKey: encrypted,
	}

	b, err := asn1.Marshal(pki)
	if err != nil {
		err = fmt.Errorf("error marshaling encrypted key: %w", err)
		return nil, err
	}
	return &pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: b,
	}, nil
}
