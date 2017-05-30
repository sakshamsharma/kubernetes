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
	"encoding/base64"
	"fmt"

	"k8s.io/apiserver/pkg/storage/value"
)

type key struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
}

// Config contains the API configuration for an AES transformer
type Config struct {
	Keys []key `json:"keys"`
}

// SanityCheck implements the TransformerConfig interface for Config
func (config Config) SanityCheck() (bool, error) {
	if len(config.Keys) == 0 {
		return false, nil
	}
	for _, key := range config.Keys {
		if key.Name == "" || key.Secret == "" {
			return true, fmt.Errorf("invalid key provided, name or secret missing")
		}
	}
	return true, nil
}

// GetPrefixTransformer implements the TransformerConfig interface for Config
func (config Config) GetPrefixTransformer() (value.PrefixTransformer, error) {
	keyTransformers := []value.PrefixTransformer{}
	var result value.PrefixTransformer

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
				Transformer: NewGCMTransformer(block),
				Prefix:      []byte(keyData.Name + ":"),
			})
	}

	// Create a prefixTransformer which can choose between these keys
	keyTransformer := value.NewPrefixTransformers(
		fmt.Errorf("no matching key was found for the provided AEAD transformer"), keyTransformers...)

	// Create a PrefixTransformer which shall later be put in a list with other providers
	result = value.PrefixTransformer{
		Transformer: keyTransformer,
		Prefix:      []byte("enc-k8s-aes-v1:"),
	}

	return result, nil
}
