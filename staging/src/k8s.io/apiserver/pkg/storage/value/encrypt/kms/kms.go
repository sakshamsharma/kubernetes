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

// Package kms transforms values for storage at rest using a KMS provider
package kms

import (
	"fmt"
	"sync"

	"k8s.io/apiserver/pkg/storage/value"

	lru "github.com/hashicorp/golang-lru"
)

// defaultCacheSize is the number of decrypted DEKs which would be cached by the transformer.
const defaultCacheSize = 1000

// Factory allows creating various cloud KMS clients for implementing KEK-DEK based KMS encryption providers.
type Factory interface {
	NewGoogleKMSService(projectID, location, keyRing, cryptoKey string) (Service, error)
}

// Service allows encrypting and decrypting data using an external Key Management Service.
type Service interface {
	// Decrypt a given data string to obtain the original byte data.
	Decrypt(data string) ([]byte, error)
	// Encrypt bytes to a string ciphertext.
	Encrypt(data []byte) (string, error)
}

type kmsTransformer struct {
	kmsService   Service
	transformers *lru.Cache

	// cacheSize is the maximum number of DEKs that are cached.
	cacheSize int

	lock sync.RWMutex
}

// NewKMSTransformer returns a transformer which implements a KEK-DEK based envelope encryption scheme.
// It uses kmsService to encrypt and decrypt DEKs. Respective DEKs (in encrypted form) are prepended to
// the data items they encrypt. A cache (of size cacheSize) is maintained to store the most recently
// used decrypted DEKs in memory.
func NewKMSTransformer(kmsService Service, cacheSize int) (value.Transformer, error) {
	if cacheSize == 0 {
		cacheSize = defaultCacheSize
	}
	return nil, fmt.Errorf("kms transformer not yet implemented")
}
