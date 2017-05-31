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

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/storage/value"
	"k8s.io/apiserver/pkg/storage/value/encrypt/identity"
)

// TransformerConfig is a blanket interface for all provider configurations
type TransformerConfig interface {
	// GetPrefixTransformer constructs and returns a PrefixTransformer using the provided configuration
	GetPrefixTransformer() (value.PrefixTransformer, error)
	// IsNil abstracts the nil check for the interface, since nil pointer checks on interface don't work
	IsNil() bool
}

// ProviderConfig stores the provided configuration for an encryption provider
type ProviderConfig struct {
	AES      *AESConfig      `json:"aes,omitempty"`
	Identity *IdentityConfig `json:"identity,omitempty"`
}

// GetPrefixTransformer returns the PrefixTransformer from the provider configuration,
// and returns an error if more than one providers were specified
func (config *ProviderConfig) GetPrefixTransformer() (value.PrefixTransformer, error) {
	var result value.PrefixTransformer
	var err error
	found := false
	for _, provider := range []TransformerConfig{config.AES, config.Identity} {
		if !provider.IsNil() {
			if found {
				return result, fmt.Errorf("more than one provider specified in a single element, should split into different list elements")
			}
			found = true
			result, err = provider.GetPrefixTransformer()
			if err != nil {
				return result, err
			}
		}
	}
	if found == false {
		return result, fmt.Errorf("invalid provider configuration provided")
	}
	return result, nil
}

// ResourceConfig stores per resource configuration
type ResourceConfig struct {
	Resources []string         `json:"resources"`
	Providers []ProviderConfig `json:"providers"`
}

// File stores the complete configuration for encryption providers
type File struct {
	Kind       string           `json:"kind"`
	APIVersion string           `json:"apiVersion"`
	Resources  []ResourceConfig `json:"resources"`
}

// GetPrefixTransformer constructs and returns the appropriate transformer from the configuration
func (config *ResourceConfig) GetPrefixTransformers() ([]value.PrefixTransformer, error) {
	var result []value.PrefixTransformer
	for _, provider := range config.Providers {
		transformer, err := provider.GetPrefixTransformer()
		if err != nil {
			return result, err
		}
		result = append(result, transformer)
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

// IdentityConfig is an empty struct to allow identity transformer in provider configuration
type IdentityConfig struct{}

// GetPrefixTransformer returns the EncryptIdentity transformer
func (*IdentityConfig) GetPrefixTransformer() (value.PrefixTransformer, error) {
	return value.PrefixTransformer{
		Transformer: identity.EncryptIdentityTransformer,
		Prefix:      []byte{},
	}, nil
}

// IsNil  implements the TransformerConfig interface for IdentityConfig
func (config *IdentityConfig) IsNil() bool {
	return config == nil
}

var _ TransformerConfig = &IdentityConfig{}
