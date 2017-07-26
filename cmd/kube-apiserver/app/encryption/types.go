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

package encryption

import (
	encryptionconfig "k8s.io/apiserver/pkg/server/options/encryption"
)

// Config stores the complete configuration for encryption providers.
type Config struct {
	// kind is the type of configuration file.
	Kind string `json:"kind"`
	// apiVersion is the API version this file has to be parsed as.
	APIVersion string `json:"apiVersion"`
	// resources is a list containing resources, and their corresponding encryption providers.
	Resources []encryptionconfig.ResourceConfig `json:"resources"`
}
