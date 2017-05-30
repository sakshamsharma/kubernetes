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

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/storage/value"
	aestransformer "k8s.io/apiserver/pkg/storage/value/encrypt/aes"
)

// Used for parsing command line parameters for selecting transformer
type EncryptionProviderConfig struct {
	TransformerMap *map[schema.GroupResource]value.Transformer
	name           string
}

func (e EncryptionProviderConfig) Set(filepath string) error {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("could not read encryption provider config from %q: %v", filepath, err)
	}

	var providers []map[string]interface{}
	yaml.Unmarshal(data, &providers)

	resourceToPrefixTransformer := map[schema.GroupResource][]value.PrefixTransformer{}

	// For each provider listed in config file
	for _, provider := range providers {
		// Parse the config map to get configuration
		providerConfig, err := parseProviderInfo(provider)
		if err != nil {
			return err
		}
		if providerConfig.Kind == "k8s-aes-gcm" {
			aead, err := aestransformer.NewGCMTransformerFromConfig(provider)
			if err != nil {
				return err
			}

			for _, resource := range providerConfig.Resource {
				resourceToPrefixTransformer[resource] = append(
					resourceToPrefixTransformer[resource], aead)
			}
		} else {
			return fmt.Errorf("found encryption provider with unknown \"kind\": %s", providerConfig.Kind)
		}
	}

	*e.TransformerMap = map[schema.GroupResource]value.Transformer{}
	for gr, transList := range resourceToPrefixTransformer {
		(*e.TransformerMap)[gr] = value.NewMutableTransformer(value.NewPrefixTransformers(fmt.Errorf("no matching prefix found"), transList...))
	}
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
	Version  string
	Resource []schema.GroupResource
}

func parseProviderInfo(config map[string]interface{}) (providerInfo, error) {
	result := providerInfo{}
	if kind, ok := config["kind"].(string); ok {
		result.Kind = kind
	} else {
		return result, fmt.Errorf("found encryption provider without a valid \"kind\" key specified in configuration")
	}

	if resources, ok := config["resource"].(string); ok {
		for _, resource := range strings.Split(resources, ",") {
			result.Resource = append(result.Resource, schema.ParseGroupResource(resource))
		}
	} else {
		return result, fmt.Errorf("ignoring encryption provider \"%s\" without a valid \"resource\" key specified in configuration", result.Kind)
	}

	// Version can be skipped
	if version, ok := config["version"]; ok {
		result.Version = "-" + fmt.Sprintf("%v", version)
	}

	return result, nil
}
