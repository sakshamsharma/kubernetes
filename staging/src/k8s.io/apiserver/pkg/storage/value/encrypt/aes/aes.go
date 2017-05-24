/*
Copyright 2017 The Kubernetes Authors.

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

// Package aes transforms values for storage at rest using AES-GCM.
package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"k8s.io/apiserver/pkg/storage/value"
)

// gcm implements AEAD encryption of the provided values given a cipher.Block algorithm.
// The authenticated data provided as part of the value.Context method must match when the same
// value is set to and loaded from storage. In order to ensure that values cannot be copied by
// an attacker from a location under their control, use characteristics of the storage location
// (such as the etcd key) as part of the authenticated data.
//
// Because this mode requires a generated IV and IV reuse is a known weakness of AES-GCM, keys
// must be rotated before a birthday attack becomes feasible. NIST SP 800-38D
// (http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf) recommends using the same
// key with random 96-bit nonces (the default nonce length) no more than 2^32 times, and
// therefore transformers using this implementation *must* ensure they allow for frequent key
// rotation. Future work should include investigation of AES-GCM-SIV as an alternative to
// random nonces.
type gcm struct {
	block cipher.Block
}

// NewGCMTransformer takes the given block cipher and performs encryption and decryption on the given
// data.
func NewGCMTransformer(block cipher.Block) value.Transformer {
	return &gcm{block: block}
}

// NewGCMTransformerFromConfig takes a configuration and creates a prefix transformer to
// handle AEAD encryption for multiple keys. Secrets must be 16, 24 or 32 bytes long,
// and encoded in base64.
// Example configuration:
// keys:
//   - name: key1
//     secret: c2VjcmV0IGlzIHNlY3VyZQ==
//   - name: key2
//     secret: dGhpcyBpcyBwYXNzd29yZA==
func NewGCMTransformerFromConfig(config map[string]interface{}) (value.Transformer, error) {

	// Obtain list of keys as []interface{}
	if keysInterface, ok := config["keys"].([]interface{}); ok {

		keyTransformers := []value.PrefixTransformer{}

		// Iterate over all keys in configuration
		for _, keyMap := range keysInterface {

			// Get the key configuration as a struct
			keyConfig, err := value.GetKeyDataFromConfig(keyMap)
			if err != nil {
				return nil, err
			}

			key, err := base64.StdEncoding.DecodeString(keyConfig.Secret)
			if err != nil {
				return nil, fmt.Errorf("could not obtain secret for named key %s: %s", keyConfig.Name, err)
			}
			block, err := aes.NewCipher(key)
			if err != nil {
				return nil, fmt.Errorf("error while creating cipher for named key %s: %s", keyConfig.Name, err)
			}

			// Create a new PrefixTransformer for this key
			keyTransformers = append(keyTransformers,
				value.PrefixTransformer{
					Transformer: NewGCMTransformer(block),
					Prefix:      []byte(keyConfig.Name + ":"),
				})
		}

		// Create a prefixTransformer which can choose between these keys
		keyTransformer := value.NewPrefixTransformers(
			fmt.Errorf("no matching key was found for the provided AEAD transformer"), keyTransformers...)

		// Create a prefixTransformer to parse the AEAD prefix
		return value.NewPrefixTransformers(nil, value.PrefixTransformer{
			Transformer: keyTransformer,
			Prefix:      []byte("k8s-aes-gcm-v1:"),
		}), nil

	} else {
		return nil, fmt.Errorf("no valid keys found in configuration for AEAD transformer")
	}
}

func (t *gcm) TransformFromStorage(data []byte, context value.Context) ([]byte, bool, error) {
	aead, err := cipher.NewGCM(t.block)
	if err != nil {
		return nil, false, err
	}
	nonceSize := aead.NonceSize()
	if len(data) < nonceSize {
		return nil, false, fmt.Errorf("the stored data was shorter than the required size")
	}
	result, err := aead.Open(nil, data[:nonceSize], data[nonceSize:], context.AuthenticatedData())
	return result, false, err
}

func (t *gcm) TransformToStorage(data []byte, context value.Context) ([]byte, error) {
	aead, err := cipher.NewGCM(t.block)
	if err != nil {
		return nil, err
	}
	nonceSize := aead.NonceSize()
	result := make([]byte, nonceSize+aead.Overhead()+len(data))
	n, err := rand.Read(result[:nonceSize])
	if err != nil {
		return nil, err
	}
	if n != nonceSize {
		return nil, fmt.Errorf("unable to read sufficient random bytes")
	}
	cipherText := aead.Seal(result[nonceSize:nonceSize], result[:nonceSize], data, context.AuthenticatedData())
	return result[:nonceSize+len(cipherText)], nil
}
