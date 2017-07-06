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

package encryptionconfig

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/storage/value"
	"k8s.io/apiserver/pkg/storage/value/encrypt/kms"
)

const (
	sampleText = "abcdefghijklmnopqrstuvwxyz"

	sampleContextText = "0123456789"

	// On change, also modify correctConfigWithKMSFirst
	testKMSCacheSize = 10

	correctConfigWithIdentityFirst = `
kind: EncryptionConfig
apiVersion: v1
resources:
  - resources:
    - secrets
    - namespaces
    providers:
    - identity: {}
    - aesgcm:
        keys:
        - name: key1
          secret: c2VjcmV0IGlzIHNlY3VyZQ==
        - name: key2
          secret: dGhpcyBpcyBwYXNzd29yZA==
    - aescbc:
        keys:
        - name: key1
          secret: c2VjcmV0IGlzIHNlY3VyZQ==
        - name: key2
          secret: dGhpcyBpcyBwYXNzd29yZA==
    - gkms:
          projectID: an-optional-project-id
          keyRing: google-kubernetes
          cryptoKey: testCryptoKey
    - secretbox:
        keys:
        - name: key1
          secret: YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
`

	correctConfigWithAesGcmFirst = `
kind: EncryptionConfig
apiVersion: v1
resources:
  - resources:
    - secrets
    providers:
    - aesgcm:
        keys:
        - name: key1
          secret: c2VjcmV0IGlzIHNlY3VyZQ==
        - name: key2
          secret: dGhpcyBpcyBwYXNzd29yZA==
    - gkms:
          projectID: an-optional-project-id
          keyRing: google-kubernetes
          cryptoKey: testCryptoKey
    - secretbox:
        keys:
        - name: key1
          secret: YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
    - aescbc:
        keys:
        - name: key1
          secret: c2VjcmV0IGlzIHNlY3VyZQ==
        - name: key2
          secret: dGhpcyBpcyBwYXNzd29yZA==
    - identity: {}
`

	correctConfigWithAesCbcFirst = `
kind: EncryptionConfig
apiVersion: v1
resources:
  - resources:
    - secrets
    providers:
    - aescbc:
        keys:
        - name: key1
          secret: c2VjcmV0IGlzIHNlY3VyZQ==
        - name: key2
          secret: dGhpcyBpcyBwYXNzd29yZA==
    - gkms:
          projectID: an-optional-project-id
          keyRing: google-kubernetes
          cryptoKey: testCryptoKey
    - identity: {}
    - secretbox:
        keys:
        - name: key1
          secret: YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
    - aesgcm:
        keys:
        - name: key1
          secret: c2VjcmV0IGlzIHNlY3VyZQ==
        - name: key2
          secret: dGhpcyBpcyBwYXNzd29yZA==
`

	correctConfigWithSecretboxFirst = `
kind: EncryptionConfig
apiVersion: v1
resources:
  - resources:
    - secrets
    providers:
    - secretbox:
        keys:
        - name: key1
          secret: YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
    - aescbc:
        keys:
        - name: key1
          secret: c2VjcmV0IGlzIHNlY3VyZQ==
        - name: key2
          secret: dGhpcyBpcyBwYXNzd29yZA==
    - gkms:
          projectID: an-optional-project-id
          keyRing: google-kubernetes
          cryptoKey: testCryptoKey
    - identity: {}
    - aesgcm:
        keys:
        - name: key1
          secret: c2VjcmV0IGlzIHNlY3VyZQ==
        - name: key2
          secret: dGhpcyBpcyBwYXNzd29yZA==
`

	correctConfigWithKMSFirst = `
kind: EncryptionConfig
apiVersion: v1
resources:
  - resources:
    - secrets
    - namespaces
    providers:
    - gkms:
          projectID: an-optional-project-id
          keyRing: google-kubernetes
          cryptoKey: testCryptoKey
          cacheSize: 10
    - aesgcm:
        keys:
        - name: key1
          secret: c2VjcmV0IGlzIHNlY3VyZQ==
        - name: key2
          secret: dGhpcyBpcyBwYXNzd29yZA==
    - identity: {}
    - aescbc:
        keys:
        - name: key1
          secret: c2VjcmV0IGlzIHNlY3VyZQ==
        - name: key2
          secret: dGhpcyBpcyBwYXNzd29yZA==
    - secretbox:
        keys:
        - name: key1
          secret: YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
`

	incorrectConfigNoSecretForKey = `
kind: EncryptionConfig
apiVersion: v1
resources:
  - resources:
    - namespaces
    - secrets
    providers:
    - aesgcm:
        keys:
        - name: key1
`

	incorrectConfigInvalidKey = `
kind: EncryptionConfig
apiVersion: v1
resources:
  - resources:
    - namespaces
    - secrets
    providers:
    - aesgcm:
        keys:
        - name: key1
          secret: c2VjcmV0IGlzIHNlY3VyZQ==
        - name: key2
          secret: YSBzZWNyZXQgYSBzZWNyZXQ=
`
)

type testKMSService struct {
	disabled bool
}

func (t *testKMSService) Decrypt(data string) ([]byte, error) {
	if t.disabled {
		return []byte{}, fmt.Errorf("KMS service was disabled")
	}
	return base64.StdEncoding.DecodeString(data)
}

func (t *testKMSService) Encrypt(data []byte) (string, error) {
	if t.disabled {
		return "", fmt.Errorf("KMS service was disabled")
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func (t *testKMSService) SetDisabledStatus(status bool) {
	t.disabled = status
}

var _ value.KMSService = &testKMSService{}

func TestEncryptionProviderConfigCorrect(t *testing.T) {
	kmsService := &testKMSService{}
	// Create a mock kmsFactory
	kmsFactory := kms.NewFactoryWithService(kmsService)

	// Creates compound/prefix transformers with different ordering of available transformers.
	// Transforms data using one of them, and tries to untransform using the others.
	// Repeats this for all possible combinations.
	identityFirstTransformerOverrides, err := ParseEncryptionConfiguration(strings.NewReader(correctConfigWithIdentityFirst), kmsFactory)
	if err != nil {
		t.Fatalf("error while parsing configuration file: %s.\nThe file was:\n%s", err, correctConfigWithIdentityFirst)
	}

	aesGcmFirstTransformerOverrides, err := ParseEncryptionConfiguration(strings.NewReader(correctConfigWithAesGcmFirst), kmsFactory)
	if err != nil {
		t.Fatalf("error while parsing configuration file: %s.\nThe file was:\n%s", err, correctConfigWithAesGcmFirst)
	}

	aesCbcFirstTransformerOverrides, err := ParseEncryptionConfiguration(strings.NewReader(correctConfigWithAesCbcFirst), kmsFactory)
	if err != nil {
		t.Fatalf("error while parsing configuration file: %s.\nThe file was:\n%s", err, correctConfigWithAesCbcFirst)
	}

	secretboxFirstTransformerOverrides, err := ParseEncryptionConfiguration(strings.NewReader(correctConfigWithSecretboxFirst), kmsFactory)
	if err != nil {
		t.Fatalf("error while parsing configuration file: %s.\nThe file was:\n%s", err, correctConfigWithSecretboxFirst)
	}

	kmsFirstTransformerOverrides, err := ParseEncryptionConfiguration(strings.NewReader(correctConfigWithKMSFirst), kmsFactory)
	if err != nil {
		t.Fatalf("error while parsing configuration file: %s.\nThe file was:\n%s", err, correctConfigWithKMSFirst)
	}

	// Pick the transformer for any of the returned resources.
	identityFirstTransformer := identityFirstTransformerOverrides[schema.ParseGroupResource("secrets")]
	aesGcmFirstTransformer := aesGcmFirstTransformerOverrides[schema.ParseGroupResource("secrets")]
	aesCbcFirstTransformer := aesCbcFirstTransformerOverrides[schema.ParseGroupResource("secrets")]
	secretboxFirstTransformer := secretboxFirstTransformerOverrides[schema.ParseGroupResource("secrets")]
	kmsFirstTransformer := kmsFirstTransformerOverrides[schema.ParseGroupResource("secrets")]

	context := value.DefaultContext([]byte(sampleContextText))
	originalText := []byte(sampleText)

	transformers := []struct {
		Transformer value.Transformer
		Name        string
	}{
		{aesGcmFirstTransformer, "aesGcmFirst"},
		{aesCbcFirstTransformer, "aesCbcFirst"},
		{secretboxFirstTransformer, "secretboxFirst"},
		{identityFirstTransformer, "identityFirst"},
		{kmsFirstTransformer, "kmsFirst"},
	}

	for _, testCase := range transformers {
		transformedData, err := testCase.Transformer.TransformToStorage(originalText, context)
		if err != nil {
			t.Fatalf("%s: error while transforming data to storage: %s", testCase.Name, err)
		}

		for _, transformer := range transformers {
			untransformedData, stale, err := transformer.Transformer.TransformFromStorage(transformedData, context)
			if err != nil {
				t.Fatalf("%s: error while reading using %s transformer: %s", testCase.Name, transformer.Name, err)
			}
			if stale != (transformer.Name != testCase.Name) {
				t.Fatalf("%s: wrong stale information on reading using %s transformer, should be %v", testCase.Name, transformer.Name, testCase.Name == transformer.Name)
			}
			if bytes.Compare(untransformedData, originalText) != 0 {
				t.Fatalf("%s: %s transformer transformed data incorrectly. Expected: %v, got %v", testCase.Name, transformer.Name, originalText, untransformedData)
			}
		}
	}

}

// Throw error if key has no secret
func TestEncryptionProviderConfigNoSecretForKey(t *testing.T) {
	if _, err := ParseEncryptionConfiguration(strings.NewReader(incorrectConfigNoSecretForKey), nil); err == nil {
		t.Fatalf("invalid configuration file (one key has no secret) got parsed:\n%s", incorrectConfigNoSecretForKey)
	}
}

// Throw error if invalid key for AES
func TestEncryptionProviderConfigInvalidKey(t *testing.T) {
	if _, err := ParseEncryptionConfiguration(strings.NewReader(incorrectConfigInvalidKey), nil); err == nil {
		t.Fatalf("invalid configuration file (bad AES key) got parsed:\n%s", incorrectConfigInvalidKey)
	}
}

// Throw error if KMS transformer tries to contact KMS without hitting cache.
func TestKMSCaching(t *testing.T) {
	kmsService := &testKMSService{}
	// Create a mock kmsFactory
	kmsFactory := kms.NewFactoryWithService(kmsService)

	kmsFirstTransformerOverrides, err := ParseEncryptionConfiguration(strings.NewReader(correctConfigWithKMSFirst), kmsFactory)
	if err != nil {
		t.Fatalf("error while parsing configuration file: %s.\nThe file was:\n%s", err, correctConfigWithKMSFirst)
	}

	kmsTransformer := kmsFirstTransformerOverrides[schema.ParseGroupResource("secrets")]
	context := value.DefaultContext([]byte(sampleContextText))
	originalText := []byte(sampleText)

	transformedData, err := kmsTransformer.TransformToStorage(originalText, context)
	if err != nil {
		t.Fatalf("kmsTransformer: error while transforming data to storage: %s", err)
	}
	untransformedData, _, err := kmsTransformer.TransformFromStorage(transformedData, context)
	if err != nil {
		t.Fatalf("could not decrypt KMS transformer's encrypted data even once: %v", err)
	}
	if bytes.Compare(untransformedData, originalText) != 0 {
		t.Fatalf("kmsTransformer transformed data incorrectly. Expected: %v, got %v", originalText, untransformedData)
	}

	kmsService.SetDisabledStatus(true)
	// Subsequent read for the same data should work fine due to caching.
	untransformedData, _, err = kmsTransformer.TransformFromStorage(transformedData, context)
	if err != nil {
		t.Fatalf("could not decrypt KMS transformer's encrypted data using just cache: %v", err)
	}
	if bytes.Compare(untransformedData, originalText) != 0 {
		t.Fatalf("kmsTransformer transformed data incorrectly using cache. Expected: %v, got %v", originalText, untransformedData)
	}
}

// Makes KMS transformer hit cache limit, throws error if it misbehaves.
func TestKMSCacheLimit(t *testing.T) {
	kmsService := &testKMSService{}
	// Create a mock kmsFactory
	kmsFactory := kms.NewFactoryWithService(kmsService)

	kmsFirstTransformerOverrides, err := ParseEncryptionConfiguration(strings.NewReader(correctConfigWithKMSFirst), kmsFactory)
	if err != nil {
		t.Fatalf("error while parsing configuration file: %s.\nThe file was:\n%s", err, correctConfigWithKMSFirst)
	}

	kmsTransformer := kmsFirstTransformerOverrides[schema.ParseGroupResource("secrets")]
	context := value.DefaultContext([]byte(sampleContextText))

	transformedOutputs := map[int][]byte{}

	// Overwrite lots of entries in the map
	for i := 0; i < 2*testKMSCacheSize; i++ {
		numberText := []byte(strconv.Itoa(i))

		res, err := kmsTransformer.TransformToStorage(numberText, context)
		transformedOutputs[i] = res
		if err != nil {
			t.Fatalf("kmsTransformer: error while transforming data (%v) to storage: %s", numberText, err)
		}
	}

	// Try reading all the data now, ensuring cache misses don't cause a concern.
	for i := 0; i < 2*testKMSCacheSize; i++ {
		numberText := []byte(strconv.Itoa(i))

		output, _, err := kmsTransformer.TransformFromStorage(transformedOutputs[i], context)
		if err != nil {
			t.Fatalf("kmsTransformer: error while transforming data (%v) from storage: %s", transformedOutputs[i], err)
		}

		if bytes.Compare(numberText, output) != 0 {
			t.Fatalf("kmsTransformer transformed data incorrectly using cache. Expected: %v, got %v", numberText, output)
		}
	}
}
