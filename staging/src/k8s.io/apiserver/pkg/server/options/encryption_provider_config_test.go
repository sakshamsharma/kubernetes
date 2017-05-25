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
	"io/ioutil"
	"os"

	"k8s.io/apiserver/pkg/storage/value"

	"testing"
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
  resource: /registry/
`

var incorrectConfig1 string = `
- kind: k8s-aes-gcm
  version: v1
  keys:
    - name: key1
    - name: key2
      secret: dGhpcyBpcyBwYXNzd29yZA==
  resource: /registry/namespaces
`

var incorrectConfig2 string = `
- kind: k8s-aes-gcm
  version: v1
  keys:
    - name: key2
      secret: dGhpcyBpcyBwYXNzd29yZA==
`

var incorrectConfig3 string = `
- kind: k8s-aes-gcm
  version: v1
  keys:
    - name: key1
      secret: YSBzZWNyZXQgYSBzZWNyZXQ=
  resource: /registry/namespaces
`

func TestEncryptionProviderConfigCorrectParsing(t *testing.T) {
	testConfigFile := ".test-enc-provider-correct"

	err := ioutil.WriteFile(testConfigFile, []byte(correctConfig), 0600)
	if err != nil {
		t.Fatalf("error while writing test configuration to disk: %s", err)
	}
	defer os.Remove(testConfigFile)

	var transformerLocation value.Transformer
	err = EncryptionProviderConfig{Transformer: &transformerLocation}.Set(testConfigFile)
	if err != nil {
		t.Fatalf("error while parsing configuration file: %s", err)
	}
}

// Throw error if key has no secret
func TestEncryptionProviderConfigIncorrectParsing1(t *testing.T) {
	testConfigFile := ".test-enc-provider-incorrect1"

	err := ioutil.WriteFile(testConfigFile, []byte(incorrectConfig1), 0600)
	if err != nil {
		t.Fatalf("error while writing test configuration to disk: %s", err)
	}
	defer os.Remove(testConfigFile)

	err = EncryptionProviderConfig{}.Set(testConfigFile)
	if err == nil {
		t.Fatalf("invalid configuration file (one key has no secret) got parsed:\n%s", incorrectConfig2)
	}
}

// Throw error if provider has no resource
func TestEncryptionProviderConfigIncorrectParsing2(t *testing.T) {
	testConfigFile := ".test-enc-provider-incorrect2"

	err := ioutil.WriteFile(testConfigFile, []byte(incorrectConfig2), 0600)
	if err != nil {
		t.Fatalf("error while writing test configuration to disk: %s", err)
	}
	defer os.Remove(testConfigFile)

	err = EncryptionProviderConfig{}.Set(testConfigFile)
	if err == nil {
		t.Fatalf("invalid configuration file (one provider has no resource) got parsed:\n%s", incorrectConfig2)
	}
}

// Throw error if invalid key for AES
func TestEncryptionProviderConfigIncorrectParsing3(t *testing.T) {
	testConfigFile := ".test-enc-provider-incorrect3"

	err := ioutil.WriteFile(testConfigFile, []byte(incorrectConfig3), 0600)
	if err != nil {
		t.Fatalf("error while writing test configuration to disk: %s", err)
	}
	defer os.Remove(testConfigFile)

	err = EncryptionProviderConfig{}.Set(testConfigFile)
	if err == nil {
		t.Fatalf("invalid configuration file (bad AES key) got parsed:\n%s", incorrectConfig2)
	}
}
