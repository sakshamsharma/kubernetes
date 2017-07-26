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

// Package encryption handles assigning encryption providers to each group resource storage.
package encryption

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"

	yaml "gopkg.in/yaml.v2"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/storage/value"
	"k8s.io/kubernetes/pkg/cloudprovider"
	kubeoptions "k8s.io/kubernetes/pkg/kubeapiserver/options"

	encryptionconfig "k8s.io/apiserver/pkg/server/options/encryption"
	"k8s.io/apiserver/pkg/storage/value/encrypt/envelope"
)

// GetTransformerOverrides returns the transformer overrides by reading and parsing the encryption provider configuration file.
// It takes cloud provider options as argument, which are used if a KMS based encryption backend is used.
func GetTransformerOverrides(encryptionConfigFilePath string, cloudProvider *kubeoptions.CloudProviderOptions) (map[schema.GroupResource]value.Transformer, error) {
	f, err := os.Open(encryptionConfigFilePath)
	if err != nil {
		return nil, fmt.Errorf("error opening encryption provider configuration file %q: %v", encryptionConfigFilePath, err)
	}
	defer f.Close()

	// Construct a function to return the named cloud provided KMS provider if needed.
	cloudKMSFunc := func(name string) (envelope.Service, error) {
		cloud, err := cloudprovider.InitCloudProvider(cloudProvider.CloudProvider, cloudProvider.CloudConfigFile)
		if err != nil {
			return nil, fmt.Errorf("cloud provider could not be initialized for using cloud provided KMS: %v", err)
		}
		if cloud == nil {
			return nil, fmt.Errorf("no cloud provided for use with cloud-provided KMS")
		}
		return cloud.KeyManagementService(name)
	}
	result, err := ParseEncryptionConfiguration(f, cloudKMSFunc)

	if err != nil {
		return nil, fmt.Errorf("error while parsing encryption provider configuration file %q: %v", encryptionConfigFilePath, err)
	}
	return result, nil
}

// ParseEncryptionConfiguration parses configuration data and returns the transformer overrides. Uses cloudKMSFunc
// to fetch a cloud-provided KMS provider if required.
func ParseEncryptionConfiguration(f io.Reader, cloudKMSFunc func(string) (envelope.Service, error)) (map[schema.GroupResource]value.Transformer, error) {
	configFileContents, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("could not read contents: %v", err)
	}

	var config Config
	err = yaml.Unmarshal(configFileContents, &config)
	if err != nil {
		return nil, fmt.Errorf("error while parsing file: %v", err)
	}

	if config.Kind != "EncryptionConfig" && config.Kind != "" {
		return nil, fmt.Errorf("invalid configuration kind %q provided", config.Kind)
	}
	if config.Kind == "" {
		return nil, fmt.Errorf("invalid configuration file, missing Kind")
	}

	resourceToPrefixTransformer := map[schema.GroupResource][]value.PrefixTransformer{}

	// For each entry in the configuration
	for _, resourceConfig := range config.Resources {
		transformers, err := encryptionconfig.GetPrefixTransformers(&resourceConfig, cloudKMSFunc)
		if err != nil {
			return nil, err
		}

		// For each resource, create a list of providers to use
		for _, resource := range resourceConfig.Resources {
			gr := schema.ParseGroupResource(resource)
			resourceToPrefixTransformer[gr] = append(
				resourceToPrefixTransformer[gr], transformers...)
		}
	}

	result := map[schema.GroupResource]value.Transformer{}
	for gr, transList := range resourceToPrefixTransformer {
		result[gr] = value.NewMutableTransformer(value.NewPrefixTransformers(fmt.Errorf("no matching prefix found"), transList...))
	}
	return result, nil
}
