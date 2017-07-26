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

package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"

	"k8s.io/apiserver/pkg/storage/value"
	aestransformer "k8s.io/apiserver/pkg/storage/value/encrypt/aes"
	"k8s.io/apiserver/pkg/storage/value/encrypt/envelope"
	"k8s.io/apiserver/pkg/storage/value/encrypt/identity"
	"k8s.io/apiserver/pkg/storage/value/encrypt/secretbox"
)

// cloudKMSFunc returns the named KMS provider as an envelope service, if provided by the cloud.
type cloudKMSFunc func(name string) (envelope.Service, error)

const (
	aesCBCTransformerPrefixV1    = "k8s:enc:aescbc:v1:"
	aesGCMTransformerPrefixV1    = "k8s:enc:aesgcm:v1:"
	secretboxTransformerPrefixV1 = "k8s:enc:secretbox:v1:"
	envelopeTransformerPrefixV1  = "k8s:enc:envelope:v1:"
)

// GetPrefixTransformers constructs and returns the appropriate prefix transformers for the passed resource using its configuration
// It uses cloudKMSFunc to get the cloudprovided KMS service if specified in the configuration.
func GetPrefixTransformers(config *ResourceConfig, cloudKMSFunc cloudKMSFunc) ([]value.PrefixTransformer, error) {
	var result []value.PrefixTransformer
	multipleProviderError := fmt.Errorf("more than one encryption provider specified in a single element, should split into different list elements")
	for _, provider := range config.Providers {
		found := false

		var transformer value.PrefixTransformer
		var err error

		if provider.AESGCM != nil {
			transformer, err = getAESPrefixTransformer(provider.AESGCM, aestransformer.NewGCMTransformer, aesGCMTransformerPrefixV1)
			if err != nil {
				return result, err
			}
			found = true
		}

		if provider.AESCBC != nil {
			if found == true {
				return result, multipleProviderError
			}
			transformer, err = getAESPrefixTransformer(provider.AESCBC, aestransformer.NewCBCTransformer, aesCBCTransformerPrefixV1)
			found = true
		}

		if provider.Secretbox != nil {
			if found == true {
				return result, multipleProviderError
			}
			transformer, err = getSecretboxPrefixTransformer(provider.Secretbox)
			found = true
		}

		if provider.CloudProvidedKMS != nil {
			if found == true {
				return result, multipleProviderError
			}
			transformer, err = getEnvelopePrefixTransformer(provider.CloudProvidedKMS, cloudKMSFunc)
			found = true
		}

		if provider.Identity != nil {
			if found == true {
				return result, multipleProviderError
			}
			transformer = value.PrefixTransformer{
				Transformer: identity.NewEncryptCheckTransformer(),
				Prefix:      []byte{},
			}
			found = true
		}

		if err != nil {
			return result, err
		}
		result = append(result, transformer)

		if found == false {
			return result, fmt.Errorf("invalid provider configuration provided")
		}
	}
	return result, nil
}

// BlockTransformerFunc taske an AES cipher block and returns a value transformer.
type BlockTransformerFunc func(cipher.Block) value.Transformer

// getAESPrefixTransformer returns a prefix transformer from the provided configuration.
// Returns an AES transformer based on the provided prefix and block transformer.
func getAESPrefixTransformer(config *AESConfig, fn BlockTransformerFunc, prefix string) (value.PrefixTransformer, error) {
	var result value.PrefixTransformer

	if len(config.Keys) == 0 {
		return result, fmt.Errorf("aes provider has no valid keys")
	}
	for _, key := range config.Keys {
		if key.Name == "" {
			return result, fmt.Errorf("key with invalid name provided")
		}
		if key.Secret == "" {
			return result, fmt.Errorf("key %v has no provided secret", key.Name)
		}
	}

	keyTransformers := []value.PrefixTransformer{}

	for _, keyData := range config.Keys {
		key, err := base64.StdEncoding.DecodeString(keyData.Secret)
		if err != nil {
			return result, fmt.Errorf("could not obtain secret for named key %s: %s", keyData.Name, err)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return result, fmt.Errorf("error while creating cipher for named key %s: %s", keyData.Name, err)
		}

		// Create a new PrefixTransformer for this key
		keyTransformers = append(keyTransformers,
			value.PrefixTransformer{
				Transformer: fn(block),
				Prefix:      []byte(keyData.Name + ":"),
			})
	}

	// Create a prefixTransformer which can choose between these keys
	keyTransformer := value.NewPrefixTransformers(
		fmt.Errorf("no matching key was found for the provided AES transformer"), keyTransformers...)

	// Create a PrefixTransformer which shall later be put in a list with other providers
	result = value.PrefixTransformer{
		Transformer: keyTransformer,
		Prefix:      []byte(prefix),
	}
	return result, nil
}

// getSecretboxPrefixTransformer returns a prefix transformer from the provided configuration
func getSecretboxPrefixTransformer(config *SecretboxConfig) (value.PrefixTransformer, error) {
	var result value.PrefixTransformer

	if len(config.Keys) == 0 {
		return result, fmt.Errorf("secretbox provider has no valid keys")
	}
	for _, key := range config.Keys {
		if key.Name == "" {
			return result, fmt.Errorf("key with invalid name provided")
		}
		if key.Secret == "" {
			return result, fmt.Errorf("key %v has no provided secret", key.Name)
		}
	}

	keyTransformers := []value.PrefixTransformer{}

	for _, keyData := range config.Keys {
		key, err := base64.StdEncoding.DecodeString(keyData.Secret)
		if err != nil {
			return result, fmt.Errorf("could not obtain secret for named key %s: %s", keyData.Name, err)
		}

		if len(key) != 32 {
			return result, fmt.Errorf("expected key size 32 for aes-cbc provider, got %v", len(key))
		}

		keyArray := [32]byte{}
		copy(keyArray[:], key)

		// Create a new PrefixTransformer for this key
		keyTransformers = append(keyTransformers,
			value.PrefixTransformer{
				Transformer: secretbox.NewSecretboxTransformer(keyArray),
				Prefix:      []byte(keyData.Name + ":"),
			})
	}

	// Create a prefixTransformer which can choose between these keys
	keyTransformer := value.NewPrefixTransformers(
		fmt.Errorf("no matching key was found for the provided Secretbox transformer"), keyTransformers...)

	// Create a PrefixTransformer which shall later be put in a list with other providers
	result = value.PrefixTransformer{
		Transformer: keyTransformer,
		Prefix:      []byte(secretboxTransformerPrefixV1),
	}
	return result, nil
}

// getEnvelopePrefixTransformer returns a prefix transformer from the provided config.
// envelopeService is used as the root of trust.
func getEnvelopePrefixTransformer(config *CloudProvidedKMSConfig, cloudKMSFunc cloudKMSFunc) (value.PrefixTransformer, error) {
	result := value.PrefixTransformer{}
	if len(config.Name) == 0 {
		return result, fmt.Errorf("no cloud provided KMS name provided")
	}
	envelopeService, err := cloudKMSFunc(config.Name)
	if err != nil {
		return result, err
	}
	if envelopeService == nil {
		return result, fmt.Errorf("cloud does not provide an implementation of KMS")
	}

	envelopeTransformer, err := envelope.NewEnvelopeTransformer(envelopeService, config.CacheSize, aestransformer.NewCBCTransformer)
	if err != nil {
		return value.PrefixTransformer{}, err
	}
	return value.PrefixTransformer{
		Transformer: envelopeTransformer,
		Prefix:      []byte(envelopeTransformerPrefixV1 + config.Name + ":"),
	}, nil
}
