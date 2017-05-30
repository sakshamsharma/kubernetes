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
kind: EncryptionConfig
apiVersion: v1
resources:
  - resources:
    - namespaces
    providers:
    - k8s-aes-v1:
        keys:
        - name: key1
          secret: c2VjcmV0IGlzIHNlY3VyZQ==
        - name: key2
          secret: dGhpcyBpcyBwYXNzd29yZA==
    - identity:
        use_prefix: no
`

var incorrectConfigNoSecretForKey string = `
kind: EncryptionConfig
apiVersion: v1
resources:
  - resources:
    - namespaces
    - secrets
    providers:
    - k8s-aes-v1:
        keys:
        - name: key1
`

var incorrectConfigInvalidKey string = `
kind: EncryptionConfig
apiVersion: v1
resources:
  - resources:
    - namespaces
    - secrets
    providers:
    - identity:
        use_prefix: no
    - k8s-aes-v1:
        keys:
        - name: key1
          secret: c2VjcmV0IGlzIHNlY3VyZQ==
		- name: key2
          secret: YSBzZWNyZXQgYSBzZWNyZXQ=
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

// Throw error if invalid key for AES
func TestEncryptionProviderConfigInvalidKey(t *testing.T) {
	var destination map[schema.GroupResource]value.Transformer
	if ConfigToTransformerOverrides(strings.NewReader(incorrectConfigInvalidKey), &destination) == nil {
		t.Fatalf("invalid configuration file (bad AES key) got parsed:\n%s", incorrectConfigInvalidKey)
	}
}
