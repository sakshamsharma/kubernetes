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

package kms

import (
	"k8s.io/kubernetes/pkg/api"

	serverstorage "k8s.io/apiserver/pkg/server/storage"
	"k8s.io/apiserver/pkg/storage/value"
)

type gceCloudGetter func() (*GCECloud, error)

// Factory provides shared instances of:
// 1. Cloud provider in use
// 2. Google KMS service override (optional)
// 3. KMS Storage wrapper
// They are used for cases with multiple transformers.
type Factory struct {
	getGCECloud gceCloudGetter

	gkmsServiceOverride value.KMSService

	storage value.KMSStorage
}

// NewFactory creates a key store for KMS data, and returns a Factory instance.
func NewFactory(storageFactory serverstorage.StorageFactory, getGCECloud gceCloudGetter) (*Factory, error) {
	storageConfig, err := storageFactory.NewConfig(api.Resource("configmap"))
	if err != nil {
		return nil, err
	}
	plainKeyStore := NewKeyStore(storageConfig, "kms")
	return &Factory{
		getGCECloud: getGCECloud,
		storage:     plainKeyStore,
	}, nil
}

// NewFactoryWithStorageAndGKMS allows creating a mockup Factory for unit tests.
func NewFactoryWithStorageAndGKMS(storage value.KMSStorage, gkmsService value.KMSService) *Factory {
	return &Factory{
		storage:             storage,
		gkmsServiceOverride: gkmsService,
	}
}

// GetGoogleKMSTransformer creates a Google KMS service which can Encrypt and Decrypt data.
// Creates a new service each time, unless there is an override.
func (kmsFactory *Factory) GetGoogleKMSTransformer(projectID, location, keyRing, cryptoKey string) (value.Transformer, error) {
	gkmsService := kmsFactory.gkmsServiceOverride
	if gkmsService == nil {
		cloud, err := kmsFactory.getGCECloud()
		if err != nil {
			return nil, err
		}
		gkmsService, err = NewGoogleKMSService(projectID, location, keyRing, cryptoKey, cloud)
		if err != nil {
			return nil, err
		}
	}
	return NewKMSTransformer(gkmsService, kmsFactory.storage)
}
