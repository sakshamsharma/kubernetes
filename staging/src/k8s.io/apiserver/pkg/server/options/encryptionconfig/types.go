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

// File stores the complete configuration for encryption providers
type File struct {
	Kind       string           `json:"kind"`
	APIVersion string           `json:"apiVersion"`
	Resources  []ResourceConfig `json:"resources"`
}

// ResourceConfig stores per resource configuration
type ResourceConfig struct {
	Resources []string         `json:"resources"`
	Providers []ProviderConfig `json:"providers"`
}

// ProviderConfig stores the provided configuration for an encryption provider
type ProviderConfig struct {
	AES      *AESConfig      `json:"aes,omitempty"`
	Identity *IdentityConfig `json:"identity,omitempty"`
}

// Config contains the API configuration for an AES transformer
type AESConfig struct {
	Keys []Key `json:"keys"`
}

// Key contains name and secret of the provided key for AES transformer
type Key struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
}

// IdentityConfig is an empty struct to allow identity transformer in provider configuration
type IdentityConfig struct{}
