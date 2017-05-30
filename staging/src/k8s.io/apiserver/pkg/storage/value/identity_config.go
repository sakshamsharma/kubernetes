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

// Package value contains methods for assisting with transformation of values in storage.
package value

import (
	"fmt"
)

type IdentityConfig struct {
	// UsePrefix serves as a sign of existance of this key
	UsePrefix string `json:"use_prefix"`
	Prefix    string `json:"prefix"`
}

func (config IdentityConfig) SanityCheck() (bool, error) {
	if config.UsePrefix == "" {
		return false, nil
	}
	return true, nil
}

func (config IdentityConfig) GetPrefixTransformer() (PrefixTransformer, error) {
	if config.UsePrefix == "yes" && config.Prefix == "" {
		return PrefixTransformer{}, fmt.Errorf("prefix not provided for identity transformer despite use_prefix being set to yes")
	}
	return PrefixTransformer{
		Transformer: IdentityTransformer,
		Prefix:      []byte(config.Prefix),
	}, nil
}
