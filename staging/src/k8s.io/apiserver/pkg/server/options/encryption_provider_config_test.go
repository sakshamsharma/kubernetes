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

package options

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/storage/value"
)

var correctConfig string = `
- kind: k8s-aes-gcm
  version: v1
  keys:
    - name: key1
      secret: c2VjcmV0IGlzIHNlY3VyZQ==
    - name: key2
      secret: dGhpcyBpcyBwYXNzd29yZA==
  resource: /registry/namespaces
- kind: k8s-aes-gcm
  version: v1
  keys:
    - name: key2
      secret: dGhpcyBpcyBwYXNzd29yZA==
    - name: key3
      secret: azhzIHNlY3JldCBzdG9yZQ==
  resource: namespaces,secrets
`

var incorrectConfigNoSecretForKey string = `
- kind: k8s-aes-gcm
  version: v1
  keys:
    - name: key1
    - name: key2
      secret: dGhpcyBpcyBwYXNzd29yZA==
  resource: namespaces,secrets
`

var incorrectConfigNoResource string = `
- kind: k8s-aes-gcm
  version: v1
  keys:
    - name: key2
      secret: dGhpcyBpcyBwYXNzd29yZA==
`

var incorrectConfigInvalidKey string = `
- kind: k8s-aes-gcm
  version: v1
  keys:
    - name: key1
      secret: YSBzZWNyZXQgYSBzZWNyZXQ=
  resource: namespaces,secrets
`

func TestEncryptionProviderConfigCorrect(t *testing.T) {
	var destination map[schema.GroupResource]value.Transformer
	if err := ConfigToTransformerOverrides(strings.NewReader(correctConfig), &destination); err != nil {
		t.Fatalf("error while parsing configuration file: %s", err)
	}
}

// Throw error if key has no secret
func TestEncryptionProviderConfigNoSecretForKey(t *testing.T) {
	var destination map[schema.GroupResource]value.Transformer
	if ConfigToTransformerOverrides(strings.NewReader(incorrectConfigNoSecretForKey), &destination) == nil {
		t.Fatalf("invalid configuration file (one key has no secret) got parsed:\n%s", incorrectConfigNoSecretForKey)
	}
}

// Throw error if provider has no resource
func TestEncryptionProviderConfigNoResource(t *testing.T) {
	var destination map[schema.GroupResource]value.Transformer
	if ConfigToTransformerOverrides(strings.NewReader(incorrectConfigNoResource), &destination) == nil {
		t.Fatalf("invalid configuration file (one provider has no resource) got parsed:\n%s", incorrectConfigNoResource)
	}
}

// Throw error if invalid key for AES
func TestEncryptionProviderConfigInvalidKey(t *testing.T) {
	var destination map[schema.GroupResource]value.Transformer
	if ConfigToTransformerOverrides(strings.NewReader(incorrectConfigInvalidKey), &destination) == nil {
		t.Fatalf("invalid configuration file (bad AES key) got parsed:\n%s", incorrectConfigInvalidKey)
	}
}
