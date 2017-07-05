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
	"k8s.io/apiserver/pkg/storage/value"
)

type gceCloudGetter func() (*GCECloud, error)

// Factory provides a way to create KMS transformers for various clouds.
type Factory struct {
	getGCECloud         gceCloudGetter
	gkmsServiceOverride value.KMSService
}

// NewFactory returns a Factory instance which can create KMS based transformers.
func NewFactory(getGCECloud gceCloudGetter) *Factory {
	return &Factory{
		getGCECloud: getGCECloud,
	}
}

// NewFactoryWithGoogleService returns a Factory instance which always uses the provided
// Google Cloud KMS service. Used for running unit tests.
func NewFactoryWithGoogleService(gkmsService value.KMSService) *Factory {
	return &Factory{
		gkmsServiceOverride: gkmsService,
	}
}

// GetGoogleKMSTransformer creates a Google KMS service which can Encrypt and Decrypt data.
// Creates a new service each time, unless there is an override.
func (kmsFactory *Factory) GetGoogleKMSTransformer(projectID, location, keyRing, cryptoKey string, cacheSize int) (value.Transformer, error) {
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

	if cacheSize == 0 {
		cacheSize = 1000
	}
	return NewKMSTransformer(gkmsService, cacheSize)
}
