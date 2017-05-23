/*
Copyright 2016 The Kubernetes Authors.

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
	"crypto/aes"
	"crypto/rand"
	"errors"
	"io/ioutil"
	"os"

	yaml "github.com/ghodss/yaml"
	"github.com/golang/glog"

	"k8s.io/apiserver/pkg/storage/value"
	aestransformer "k8s.io/apiserver/pkg/storage/value/encrypt/aes"
)

func newAesTransformer(key []byte) (value.Transformer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return aestransformer.NewGCMTransformer(block), nil
}

func readKeyOrGenKey(filename string, size int) ([]byte, error) {
	_, err := os.Stat(filename)

	if os.IsNotExist(err) {
		// Generate a new key and store it in the provided file
		key := make([]byte, size)
		_, err := rand.Read(key)
		if err != nil {
			return nil, err
		}
		ioutil.WriteFile(filename, key, 0600)
		return key, nil

	} else if err == nil {
		// Simply read the file and return the key
		return ioutil.ReadFile(filename)

	} else {
		// Other miscellaneous errors
		return nil, err
	}
}

// Used for parsing command line parameters for selecting transformer
type EncryptionProviderConfig struct {
	Transf *value.Transformer
	name   string
}

func (e EncryptionProviderConfig) Set(filepath string) error {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return err
	}

	var providers []map[string]interface{}
	yaml.Unmarshal(data, &providers)

	// The final transformer which will be wrapped inside a mutable transformer
	var transformer value.Transformer

	for provider := range providers {
		if kind, ok := provider["kind"]; ok {
			if kind == "AEAD" {
			}

		} else {
			glog.Warningf("ignoring encryption provider without \"kind\" key specified in configuration")
		}
	}

	if config.Kind == "AEAD" {
		// TODO Replace this with automatic key generation
		if len(config.Keys) == 0 {
			return errors.New("no key files provided")
		}
		if len(config.Keys) > 1 {
			glog.Warningf("more than one key not supported for local AEAD without KEK-DEK, but found %d key files", len(config.Keys))
		}

		// We need to generate a random key if the provided file did not exist
		// Otherwise simply read from the provided file
		key, err := readKeyOrGenKey(config.Keys[0], 32)
		if err != nil {
			return err
		}

		// The key is validated while creating the new cipher
		*e.Transf, err = newAesTransformer(key)
		if err != nil {
			return err
		}
	} else {
		return errors.New("unknown encryption kind provided in configuration: " + config.Kind)
	}
	return nil
}

func (e EncryptionProviderConfig) String() string {
	return e.name
}

func (e EncryptionProviderConfig) Type() string {
	return "encryption-provider-config"
}
