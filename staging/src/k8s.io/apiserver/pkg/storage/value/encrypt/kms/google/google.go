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

package google

import (
	"encoding/base64"
	"fmt"

	cloudkms "google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/googleapi"
)

const defaultGKMSKeyRing = "google-kubernetes"

// GKMSService provides Encrypt and Decrypt methods which allow cryptographic operations
// using Google Cloud KMS service. It implements kms.Service interface.
type GKMSService struct {
	parentName      string
	cloudkmsService *cloudkms.Service
}

// NewGoogleKMSService creates a Google KMS connection and returns a GKMSService instance which can encrypt and decrypt data.
func NewGoogleKMSService(projectID, location, keyRing, cryptoKey string, cloud *cloudkms.Service) (*GKMSService, error) {
	// Default location and keyRing for keys
	if len(location) == 0 {
		location = "global"
	}
	if len(keyRing) == 0 {
		keyRing = defaultGKMSKeyRing
	}

	if len(projectID) == 0 {
		return nil, fmt.Errorf("missing projectID in encryption provider configuration for gkms provider")
	}
	if len(cryptoKey) == 0 {
		return nil, fmt.Errorf("missing cryptoKey in encryption provider configuration for gkms provider")
	}

	parentName := fmt.Sprintf("projects/%s/locations/%s", projectID, location)

	// Create the keyRing if it does not exist yet
	_, err := cloud.Projects.Locations.KeyRings.Create(parentName,
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
	_, err = cloud.Projects.Locations.KeyRings.CryptoKeys.Create(parentName,
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

	return &GKMSService{
		parentName:      parentName,
		cloudkmsService: cloud,
	}, nil
}

// Decrypt decrypts a base64 representation of encrypted bytes.
func (t *GKMSService) Decrypt(data string) ([]byte, error) {
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
func (t *GKMSService) Encrypt(data []byte) (string, error) {
	resp, err := t.cloudkmsService.Projects.Locations.KeyRings.CryptoKeys.
		Encrypt(t.parentName, &cloudkms.EncryptRequest{
			Plaintext: base64.StdEncoding.EncodeToString(data),
		}).Do()
	if err != nil {
		return "", err
	}
	return resp.Ciphertext, nil
}
