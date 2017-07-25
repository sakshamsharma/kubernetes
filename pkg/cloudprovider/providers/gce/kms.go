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

package gce

import (
	"encoding/base64"
	"fmt"

	"k8s.io/kubernetes/pkg/cloudprovider"

	cloudkms "google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/googleapi"
)

const (
	KMSServiceName = "google-cloudkms"

	defaultGKMSKeyRing = "google-kubernetes"
)

// gkmsConfig contains the GCE specific KMS configuration for setting up a KMS connection.
type gkmsConfig struct {
	// location is the KMS location of the KeyRing to be used for encryption. The default value is "global".
	// It can be found by checking the available KeyRings in the IAM UI.
	// This is not the same as the GCP location of the project.
	// +optional
	Location string
	// keyRing is the keyRing of the hosted key to be used. The default value is "google-kubernetes".
	// +optional
	KeyRing string
	// cryptoKey is the name of the key to be used for encryption of Data-Encryption-Keys.
	CryptoKey string
}

// gkmsService provides Encrypt and Decrypt methods which allow cryptographic operations
// using Google Cloud KMS service.
type gkmsService struct {
	parentName      string
	cloudkmsService *cloudkms.Service
}

// KeyManagementService returns a named key management service supported by the cloud.
func (gce *GCECloud) KeyManagementService(name string) (cloudprovider.KeyManagementService, error) {
	if name != KMSServiceName {
		return nil, fmt.Errorf("cloud %q does not support KeyManagementService %q", gce.ProviderName(), name)
	}

	if gce.kmsConfig == nil {
		return nil, fmt.Errorf("kmsConfig not provided in GCE cloud configuration")
	}

	// Hosting on GCE/GKE with Google KMS encryption provider
	cloudkmsService := gce.GetKMSService()

	// Set defaults for location and keyRing.
	location := gce.kmsConfig.Location
	if len(location) == 0 {
		location = "global"
	}
	keyRing := gce.kmsConfig.KeyRing
	if len(keyRing) == 0 {
		keyRing = defaultGKMSKeyRing
	}

	cryptoKey := gce.kmsConfig.CryptoKey
	if len(cryptoKey) == 0 {
		return nil, fmt.Errorf("missing cryptoKey for cloudprovided KMS: " + KMSServiceName)
	}

	parentName := fmt.Sprintf("projects/%s/locations/%s", gce.projectID, location)

	// Create the keyRing if it does not exist yet
	_, err := cloudkmsService.Projects.Locations.KeyRings.Create(parentName,
		&cloudkms.KeyRing{}).KeyRingId(keyRing).Do()
	if err != nil && unrecoverableCreationError(err) {
		return nil, err
	}
	parentName = parentName + "/keyRings/" + keyRing

	// Create the cryptoKey if it does not exist yet
	_, err = cloudkmsService.Projects.Locations.KeyRings.CryptoKeys.Create(parentName,
		&cloudkms.CryptoKey{
			Purpose: "ENCRYPT_DECRYPT",
		}).CryptoKeyId(cryptoKey).Do()
	if err != nil && unrecoverableCreationError(err) {
		return nil, err
	}
	parentName = parentName + "/cryptoKeys/" + cryptoKey

	service := &gkmsService{
		parentName:      parentName,
		cloudkmsService: cloudkmsService,
	}

	// Sanity check before startup. For non-GCP clusters, the user's account may not have permissions to create
	// the key. We need to verify the existence of the key before apiserver startup.
	_, err = service.Encrypt([]byte("test"))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data using Google cloudkms, using key %s. Ensure that the keyRing and cryptoKey exist. Got error: %v", parentName, err)
	}

	return service, nil
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

// unrecoverableCreationError decides if Kubernetes should ignore the encountered Google KMS
// error. Only to be used for errors seen while creating a KeyRing or CryptoKey.
func unrecoverableCreationError(err error) bool {
	apiError, isAPIError := err.(*googleapi.Error)
	// 409 means the object exists.
	// 403 means we do not have permission to create the object, the user must do it.
	// Else, it is an unrecoverable error.
	if !isAPIError || (apiError.Code != 409 && apiError.Code != 403) {
		return true
	}
	return false
}
