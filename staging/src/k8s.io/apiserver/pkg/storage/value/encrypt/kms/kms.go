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
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"

	"k8s.io/apiserver/pkg/storage/value"
	aestransformer "k8s.io/apiserver/pkg/storage/value/encrypt/aes"

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
	// CheckStale checks if the provided encrypted text is stale and needs to be re-encrypted.
	CheckStale(data string) (bool, error)
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
	cache, err := lru.New(cacheSize)
	if err != nil {
		return nil, err
	}
	return &kmsTransformer{
		kmsService:   kmsService,
		transformers: cache,
		cacheSize:    cacheSize,
	}, nil
}

// TransformFromStorage decrypts data encrypted by this transformer using envelope encryption.
func (t *kmsTransformer) TransformFromStorage(data []byte, context value.Context) ([]byte, bool, error) {
	t.lock.RLock()
	defer t.lock.RUnlock()

	// Length of key can be encoded in 16 bits.
	keyLen := int(binary.BigEndian.Uint16(data[:2]))
	if keyLen+2 > len(data) {
		return []byte{}, false, fmt.Errorf("invalid data encountered by gkms transformer, length longer than available bytes: %q", data)
	}
	encKey := string(data[2 : keyLen+2])
	encData := data[2+keyLen:]

	var transformer value.Transformer
	var kmsStale bool
	_transformer, found := t.transformers.Get(encKey)
	if found {
		transformer = _transformer.(value.Transformer)
	} else {
		key, err := t.kmsService.Decrypt(encKey)
		if err != nil {
			return []byte{}, false, fmt.Errorf("error while decrypting key: %q", err)
		}

		// We need to release the read lock to prevent a deadlock
		t.lock.RUnlock()
		transformer, err = t.addTransformer(encKey, key)
		t.lock.RLock()

		if err != nil {
			return []byte{}, false, err
		}
	}
	kmsStale, err := t.kmsService.CheckStale(encKey)
	if err != nil {
		return []byte{}, false, err
	}
	res, transformerStale, err := transformer.TransformFromStorage(encData, context)
	return res, (transformerStale || kmsStale), err
}

// TransformToStorage encrypts data to be written to disk using envelope encryption.
func (t *kmsTransformer) TransformToStorage(data []byte, context value.Context) ([]byte, error) {
	newKey, err := generateKey(32)
	if err != nil {
		return []byte{}, err
	}

	encKey, err := t.kmsService.Encrypt(newKey)
	if err != nil {
		return []byte{}, err
	}

	transformer, err := t.addTransformer(encKey, newKey)
	if err != nil {
		return []byte{}, err
	}

	encKeyLen := make([]byte, 2)
	encKeyBytes := []byte(encKey)
	binary.BigEndian.PutUint16(encKeyLen, uint16(len(encKeyBytes)))

	prefix := append(encKeyLen, encKeyBytes...)

	prefixedData := make([]byte, len(prefix), len(data)+len(prefix))
	copy(prefixedData, prefix)
	result, err := transformer.TransformToStorage(data, context)
	if err != nil {
		return nil, err
	}
	prefixedData = append(prefixedData, result...)
	return prefixedData, nil
}

var _ value.Transformer = &kmsTransformer{}

// addTransformer inserts a new transformer to the KMS cache of DEKs for future reads.
func (t *kmsTransformer) addTransformer(encKey string, key []byte) (value.Transformer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	transformer := aestransformer.NewCBCTransformer(block)

	t.lock.Lock()
	t.transformers.Add(encKey, transformer)
	t.lock.Unlock()
	return transformer, nil
}

// generateKey generates a random key using system randomness.
func generateKey(length int) ([]byte, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return []byte{}, err
	}

	return key, nil
}
