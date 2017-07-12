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

package cloudprovider

import (
	"context"
	"encoding/base64"
	"fmt"

	"golang.org/x/oauth2/google"

	cloudkms "google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/googleapi"
	"k8s.io/apiserver/pkg/storage/value/encrypt/kms"
	"k8s.io/kubernetes/pkg/cloudprovider"
	"k8s.io/kubernetes/pkg/cloudprovider/providers/gce"
)

const defaultGKMSKeyRing = "google-kubernetes"

type kmsServiceFactory struct {
	cloudName      string
	configFilePath string
}

// NewKMSFactory creates a kms.Factory which can provide various cloud KMS services.
func NewKMSFactory(name, configFilePath string) kms.Factory {
	return &kmsServiceFactory{
		cloudName:      name,
		configFilePath: configFilePath,
	}
}

// gkmsService provides Encrypt and Decrypt methods which allow cryptographic operations
// using Google Cloud KMS service. It implements kms.Service interface.
type gkmsService struct {
	parentName      string
	cloudkmsService *cloudkms.Service
}

// NewGoogleKMSService creates a Google KMS connection and returns a kms.Service instance which can encrypt and decrypt data.}
func (k *kmsServiceFactory) NewGoogleKMSService(projectID, location, keyRing, cryptoKey string) (kms.Service, error) {
	cloud, err := cloudprovider.InitCloudProvider(k.cloudName, k.configFilePath)
	if err != nil {
		return nil, fmt.Errorf("cloud provider could not be initialized: %v", err)
	}

	var cloudkmsService *cloudkms.Service
	var cloudProjectID string

	// This check is false if cloud is nil, or is not an instance of gce.GCECloud.
	if gke, ok := cloud.(*gce.GCECloud); ok {
		// Hosting on GCE/GKE with Google KMS encryption provider
		cloudkmsService = gke.GetKMSService()

		// Project ID is assumed to be the user's project unless there
		// is an override in the configuration file. If there is an override,
		// it will be taken into account by the Google KMS service constructor,
		// after reading the configuration file.
		cloudProjectID = gke.ProjectID()
	} else {
		// When running outside GCE/GKE and connecting to KMS, GOOGLE_APPLICATION_CREDENTIALS
		// environment variable is required. This describes how that can be done:
		// https://developers.google.com/identity/protocols/application-default-credentials
		ctx := context.Background()
		client, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
		if err != nil {
			return nil, err
		}
		cloudkmsService, err = cloudkms.New(client)
		if err != nil {
			return nil, err
		}
		cloudProjectID = ""
	}

	// Default location and keyRing for keys
	if len(location) == 0 {
		location = "global"
	}
	if len(keyRing) == 0 {
		keyRing = defaultGKMSKeyRing
	}

	if len(projectID) == 0 {
		projectID = cloudProjectID
	}
	if len(projectID) == 0 {
		return nil, fmt.Errorf("missing projectID in encryption provider configuration for gkms provider")
	}
	if len(cryptoKey) == 0 {
		return nil, fmt.Errorf("missing cryptoKey in encryption provider configuration for gkms provider")
	}

	parentName := fmt.Sprintf("projects/%s/locations/%s", projectID, location)

	// Create the keyRing if it does not exist yet
	_, err = cloudkmsService.Projects.Locations.KeyRings.Create(parentName,
		&cloudkms.KeyRing{}).KeyRingId(keyRing).Do()
	if err != nil {
		apiError, ok := err.(*googleapi.Error)
		// If it was a 409, that means the keyring existed.
		// If it was a 403, we do not have permission to create the keyring, the user must do it.
		// Else, it is an unrecoverable error.
		if !ok || (apiError.Code != 409 && apiError.Code != 403) {
			return nil, err
		}
	}
	parentName = parentName + "/keyRings/" + keyRing

	// Create the cryptoKey if it does not exist yet
	_, err = cloudkmsService.Projects.Locations.KeyRings.CryptoKeys.Create(parentName,
		&cloudkms.CryptoKey{
			Purpose: "ENCRYPT_DECRYPT",
		}).CryptoKeyId(cryptoKey).Do()
	if err != nil {
		apiError, ok := err.(*googleapi.Error)
		// If it was a 409, that means the key existed.
		// If it was a 403, we do not have permission to create the key, the user must do it.
		// Else, it is an unrecoverable error.
		if !ok || (apiError.Code != 409 && apiError.Code != 403) {
			return nil, err
		}
	}
	parentName = parentName + "/cryptoKeys/" + cryptoKey

	return &gkmsService{
		parentName:      parentName,
		cloudkmsService: cloudkmsService,
	}, nil
}

// Decrypt decrypts a base64 representation of encrypted bytes.
func (t *gkmsService) Decrypt(data string) ([]byte, error) {
	resp, err := t.cloudkmsService.Projects.Locations.KeyRings.CryptoKeys.
		Decrypt(t.parentName, &cloudkms.DecryptRequest{
			Ciphertext: data,
		}).Do()
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(resp.Plaintext)
}

// Encrypt encrypts bytes, and returns base64 representation of the ciphertext.
func (t *gkmsService) Encrypt(data []byte) (string, error) {
	resp, err := t.cloudkmsService.Projects.Locations.KeyRings.CryptoKeys.
		Encrypt(t.parentName, &cloudkms.EncryptRequest{
			Plaintext: base64.StdEncoding.EncodeToString(data),
		}).Do()
	if err != nil {
		return "", err
	}
	return resp.Ciphertext, nil
}
