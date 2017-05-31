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

package config

import (
	"fmt"

	yaml "github.com/ghodss/yaml"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/storage/value"
)

// ResourceConfig stores per resource configuration
type ResourceConfig struct {
	Resources []string         `json:"resources"`
	Providers []ProviderParser `json:"providers"`
}

// File stores the complete configuration for encryption providers
type File struct {
	Kind       string           `json:"kind"`
	APIVersion string           `json:"apiVersion"`
	Resources  []ResourceConfig `json:"resources"`
}

// GetPrefixTransformer constructs and returns the appropriate transformer from the configuration.
func (config *ResourceConfig) GetPrefixTransformer() ([]value.PrefixTransformer, error) {

	var result []value.PrefixTransformer

	for _, provider := range config.Providers {
		result = append(result, provider.Transformer)
	}

	return result, nil
}

// GetGroupResources returns a slice of group resources which have to be encrypted using this provider.
func (config *ResourceConfig) GetGroupResources() []schema.GroupResource {
	resources := []schema.GroupResource{}
	for _, resource := range config.Resources {
		resources = append(resources, schema.ParseGroupResource(resource))
	}
	return resources
}

// ProviderParser helps parse the configured providers for resources.
type ProviderParser struct {
	Transformer value.PrefixTransformer
}

// UnmarshalJSON allows obtaining ProviderParser from []byte
// Preferable because it allows us to parse identity as a string.
func (p *ProviderParser) UnmarshalJSON(b []byte) error {
	parsedName := struct {
		Type string `json:"type"`
	}{}
	err := yaml.Unmarshal(b, &parsedName)
	if err != nil {
		return err
	}

	if parsedName.Type == "identity" {
		p.Transformer = value.PrefixTransformer{
			Transformer: value.IdentityTransformer,
			Prefix:      []byte{},
		}
	} else if parsedName.Type == "aes" {
		aesParsed := AesConfig{}
		err = yaml.Unmarshal(b, &aesParsed)
		if err != nil {
			return err
		}
		p.Transformer, err = aesParsed.GetPrefixTransformer()
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("unknown type of provider passed: %v", parsedName.Type)
	}
	return nil
}
