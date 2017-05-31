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

	yaml "github.com/ghodss/yaml"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/storage/value"

	encryptionconfig "k8s.io/apiserver/pkg/server/options/encryptionconfig"
)

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

	var config encryptionconfig.File
	err = yaml.Unmarshal(configFileContents, &config)
	if err != nil {
		return fmt.Errorf("error while parsing configuration: %v", err)
	}

	if config.Kind != "EncryptionConfig" && config.Kind != "" {
		return fmt.Errorf("invalid configuration kind provided for encryption provider config: " + config.Kind)
	}
	if config.Kind == "" {
		return fmt.Errorf("invalid configuration file provided")
	}
	// TODO config.APIVersion is unchecked

	resourceToPrefixTransformer := map[schema.GroupResource][]value.PrefixTransformer{}

	// For each provider listed in config file
	for _, resourceConfig := range config.Resources {
		transformers, err := resourceConfig.GetPrefixTransformers()
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
