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
	cloudkms "google.golang.org/api/cloudkms/v1"
	"k8s.io/apiserver/pkg/storage/value"
	"k8s.io/apiserver/pkg/storage/value/encrypt/kms/google"
)

// CloudKMSServiceFactory provides a way to obtain various KMS services needed for implementing KMS based encryption-providers.
type CloudKMSServiceFactory interface {
	GetGoogleKMSService() (*cloudkms.Service, string, error)
}

// Factory provides a way to create KMS transformers for various clouds.
type Factory interface {
	GetGoogleKMSTransformer(projectID, location, keyRing, cryptoKey string, cacheSize int) (value.Transformer, error)
}

type factory struct {
	kmsServiceFactory CloudKMSServiceFactory
}

// NewFactory creates a Factory using the provided KMS service factory.
func NewFactory(kmsServiceFactory CloudKMSServiceFactory) Factory {
	return &factory{
		kmsServiceFactory: kmsServiceFactory,
	}
}

// GetGoogleKMSTransformer creates a Google KMS service which can Encrypt and Decrypt data.
func (factory *factory) GetGoogleKMSTransformer(projectID, location, keyRing, cryptoKey string, cacheSize int) (value.Transformer, error) {
	cloud, cloudProjectID, err := factory.kmsServiceFactory.GetGoogleKMSService()
	if err != nil {
		return nil, err
	}
	if len(projectID) == 0 {
		projectID = cloudProjectID
	}
	gkmsService, err := google.NewGoogleKMSService(projectID, location, keyRing, cryptoKey, cloud)
	if err != nil {
		return nil, err
	}
	return NewKMSTransformer(gkmsService, cacheSize)
}

type factoryFromService struct {
	service Service
}

// NewFactoryFromService returns a Factory instance which always uses the provided service to create a
// KMS transformer. Useful for unit tests.
func NewFactoryFromService(service Service) Factory {
	return &factoryFromService{
		service: service,
	}
}

func (factory *factoryFromService) GetGoogleKMSTransformer(_, _, _, _ string, cacheSize int) (value.Transformer, error) {
	return NewKMSTransformer(factory.service, cacheSize)
}
