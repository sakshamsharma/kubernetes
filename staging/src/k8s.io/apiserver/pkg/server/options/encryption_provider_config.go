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
	"fmt"
	"io/ioutil"
	"strings"

	yaml "github.com/ghodss/yaml"

	"k8s.io/apiserver/pkg/storage/value"
	aestransformer "k8s.io/apiserver/pkg/storage/value/encrypt/aes"
)

// Used for parsing command line parameters for selecting transformer
type EncryptionProviderConfig struct {
	Transformer *value.Transformer
	name        string
}

func (e EncryptionProviderConfig) Set(filepath string) error {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("could not read encryption provider config from %q: %v", filepath, err)
	}

	var providers []map[string]interface{}
	yaml.Unmarshal(data, &providers)

	// The final transformers which will be wrapped inside a location transformer, and then a mutable transformer
	transformers := []value.LocationTransformer{}

	// For each provider listed in config file
	for _, provider := range providers {
		// Parse the config map to get configuration
		providerConfig, err := parseProviderInfo(provider)
		if err != nil {
			return err
		}
		if providerConfig.Kind == "AEAD" {
			aead, err := aestransformer.NewGCMTransformerFromConfig(provider)
			if err != nil {
				return err
			}
			transformers = append(transformers,
				value.LocationTransformer{Transformer: aead, Location: providerConfig.Resource})
		} else {
			return fmt.Errorf("found encryption provider with unknown \"kind\": %s", providerConfig.Kind)
		}
	}

	locationTransformer := value.NewLocationTransformers(fmt.Errorf("no such transformer found"), transformers...)
	*e.Transformer = value.NewMutableTransformer(locationTransformer)
	return nil
}

func (e EncryptionProviderConfig) String() string {
	return e.name
}

func (e EncryptionProviderConfig) Type() string {
	return "experimental-encryption-provider-config"
}

// Stores information common to all encryption providers
type providerInfo struct {
	Kind     string
	Resource string
}

func parseProviderInfo(config map[string]interface{}) (providerInfo, error) {
	result := providerInfo{}
	if kind, ok := config["kind"].(string); ok {
		result.Kind = kind
	} else {
		return result, fmt.Errorf("found encryption provider without a valid \"kind\" key specified in configuration")
	}

	if resource, ok := config["resource"].(string); ok {
		if !strings.HasSuffix(resource, "/") {
			resource = resource + "/"
		}
		result.Resource = resource
	} else {
		return result, fmt.Errorf("ignoring encryption provider \"%s\" without a valid \"resource\" key specified in configuration", result.Kind)
	}

	return result, nil
}
