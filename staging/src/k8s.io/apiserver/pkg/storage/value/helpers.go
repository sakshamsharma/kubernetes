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

package value

import (
	"fmt"
)

// KeyConfig contains the name of the key, and the file in which it is stored
type KeyConfig struct {
	Name   string
	Secret string
}

// GetKeyDataFromConfig parses a valid interface to a KeyConfig object
func GetKeyDataFromConfig(config interface{}) (KeyConfig, error) {
	keyItem := config.(map[string]interface{})

	keyConfigToReturn := KeyConfig{}
	if name, ok := keyItem["name"].(string); ok {
		keyConfigToReturn.Name = name
	} else {
		return keyConfigToReturn, fmt.Errorf("found a key without a name parameter")
	}

	if secret, ok := keyItem["secret"].(string); ok {
		keyConfigToReturn.Secret = secret
	} else {
		return keyConfigToReturn, fmt.Errorf("found key \"%s\" without a secret", keyConfigToReturn.Name)
	}
	return keyConfigToReturn, nil
}
