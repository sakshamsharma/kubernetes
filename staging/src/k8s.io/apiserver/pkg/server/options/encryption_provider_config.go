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
	"io"
	"io/ioutil"
	"os"
	"strings"

	yaml "github.com/ghodss/yaml"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/storage/value"
	"k8s.io/apiserver/pkg/storage/value/encrypt/aes"
)

// ProviderConfig stores the provided configuration for a provider
type ProviderConfig struct {
	AesConfig aes.Config `json:"k8s-aes-v1"`
}

type ResourceConfig struct {
	Resources []string         `json:"resources"`
	Providers []ProviderConfig `json:"providers"`
}

type ConfigFile struct {
	Kind       string           `json:"kind"`
	ApiVersion string           `json:"apiVersion"`
	Resources  []ResourceConfig `json:"resources"`
}

// GetPrefixTransformer constructs and returns the appropriate transformer from the configuration
func (config *ResourceConfig) GetPrefixTransformer() ([]value.PrefixTransformer, error) {

	var result []value.PrefixTransformer

	// For each provider listed for these resources
	for _, providerConfig := range config.Providers {

		// Whether we found a parsable transformer configuration
		found := false

		// Try which transformer is requested to be configured
		for _, transformerConfig := range []value.TransformerConfig{providerConfig.AesConfig} {
			// Check whether the configuration exists, and is valid
			exists, err := transformerConfig.SanityCheck()
			if exists && err == nil {
				// If this configuration was provided, and there was no parse error while reading it
				transformer, err := transformerConfig.GetPrefixTransformer()
				if err != nil {
					return result, err
				}
				result = append(result, transformer)
				found = true
			} else if exists {
				// If this configuration was provided, but it could not be parsed
				return result, err
			}
			// else the configuration was not provided, in which case exists was false
		}

		if !found {
			return result, fmt.Errorf("no valid encryption provider was specified for resources: " + strings.Join(config.Resources, ","))
		}
	}

	return result, nil
}

// GetGroupResources returns a slice of group resources which have to be encrypted using this provider
func (config *ResourceConfig) GetGroupResources() []schema.GroupResource {
	resources := []schema.GroupResource{}
	for _, resource := range config.Resources {
		resources = append(resources, schema.ParseGroupResource(resource))
	}
	return resources
}

// EncryptionProviderOverrides is used for passing parsed information information from CLI flag to storageConfig
type EncryptionProviderOverrides struct {
	TransformerOverrides *map[schema.GroupResource]value.Transformer
}

func (e EncryptionProviderOverrides) Set(filepath string) error {
	f, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("error opening encryption provider configuration file %q: %v", filepath, err)
	}
	defer f.Close()

	if err := ConfigToTransformerOverrides(f, e.TransformerOverrides); err != nil {
		return fmt.Errorf("error parsing encryption provider configuration file %q: %v", filepath, err)
	}
	return nil
}

func (e EncryptionProviderOverrides) String() string {
	return "<undefined>"
}

func (e EncryptionProviderOverrides) Type() string {
	return "experimental-encryption-provider-config"
}

// ConfigToTransformerOverrides consumes an io.Reader containing a configuration file, and stores
// the parsed encryption provider configuration to destination
func ConfigToTransformerOverrides(f io.Reader, destination *map[schema.GroupResource]value.Transformer) error {
	configFileContents, err := ioutil.ReadAll(f)
	if err != nil {
		return fmt.Errorf("could not read contents: %v", err)
	}

	var config ConfigFile
	err = yaml.Unmarshal(configFileContents, &config)
	if err != nil {
		return fmt.Errorf("error while parsing configuration: %v", err)
	}

	if config.Kind != "EncryptionConfig" {
		return fmt.Errorf("invalid configuration kind provided for encryption provider config")
	}
	// TODO config.ApiVersion is unchecked

	resourceToPrefixTransformer := map[schema.GroupResource][]value.PrefixTransformer{}

	// For each provider listed in config file
	for _, resourceConfig := range config.Resources {
		transformers, err := resourceConfig.GetPrefixTransformer()
		if err != nil {
			return err
		}

		// For each of the resource, create a list of providers to use
		for _, resource := range resourceConfig.GetGroupResources() {
			resourceToPrefixTransformer[resource] = append(
				resourceToPrefixTransformer[resource], transformers...)
		}
	}

	*destination = map[schema.GroupResource]value.Transformer{}
	for gr, transList := range resourceToPrefixTransformer {
		(*destination)[gr] = value.NewMutableTransformer(value.NewPrefixTransformers(fmt.Errorf("no matching prefix found"), transList...))
	}
	return nil
}
