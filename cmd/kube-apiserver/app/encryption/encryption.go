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
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/server/options/encryptionconfig"
	"k8s.io/apiserver/pkg/storage/value"
	"k8s.io/apiserver/pkg/storage/value/encrypt/kms"
	"k8s.io/kubernetes/pkg/cloudprovider"
	kubeoptions "k8s.io/kubernetes/pkg/kubeapiserver/options"
)

// GetTransformerOverrides creates a map of transformer overrides, one for each group resource which was
// specified in the configuration file configFilePath. cloudProvider would be used to connect to a cloud
// when using Cloud KMS services.
func GetTransformerOverrides(configFilePath string, cloudProvider *kubeoptions.CloudProviderOptions) (map[schema.GroupResource]value.Transformer, error) {
	transformerOverrides, err := encryptionconfig.GetTransformerOverrides(
		configFilePath,
		func(name string, kmsConfig map[string]interface{}) (kms.Service, error) {
			return cloudprovider.InitKMSService(cloudProvider.CloudProvider, cloudProvider.CloudConfigFile, name, kmsConfig)
		})
	if err != nil {
		return nil, err
	}
	return transformerOverrides, nil
}
