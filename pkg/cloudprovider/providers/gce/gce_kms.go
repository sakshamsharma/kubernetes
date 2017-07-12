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
	"context"
	"encoding/base64"
	"fmt"

	"github.com/mitchellh/mapstructure"

	"golang.org/x/oauth2/google"
	cloudkms "google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/googleapi"
	"k8s.io/kubernetes/pkg/cloudprovider"
)

const (
	KMSServiceName = "google-cloudkms"

	defaultGKMSKeyRing = "google-kubernetes"
)

type KMSConfig struct {
	// projectID is the GCP project which hosts the key to be used. It defaults to the GCP project
	// in use, if you are running on Kubernetes on GKE/GCE. Setting this field will override
	// the default. It is not optional if Kubernetes is not on GKE/GCE.
	// +optional
	ProjectID string `json:"projectID,omitempty"`
	// location is the KMS location of the KeyRing to be used for encryption. The default value is "global".
	// It can be found by checking the available KeyRings in the IAM UI.
	// This is not the same as the GCP location of the project.
	// +optional
	Location string `json:"location,omitempty"`
	// keyRing is the keyRing of the hosted key to be used. The default value is "google-kubernetes".
	// +optional
	KeyRing string `json:"keyRing,omitempty"`
	// cryptoKey is the name of the key to be used for encryption of Data-Encryption-Keys.
	CryptoKey string `json:"cryptoKey,omitempty"`
}

func init() {
	cloudprovider.RegisterKMSService(
		KMSServiceName,
		func(cloud cloudprovider.Interface, config map[string]interface{}) (cloudprovider.KMSService, error) {
			return newGoogleKMSService(cloud, config)
		})
}

// gkmsService provides Encrypt and Decrypt methods which allow cryptographic operations
// using Google Cloud KMS service.
type gkmsService struct {
	parentName      string
	cloudkmsService *cloudkms.Service
}

// newGoogleKMSService creates a Google KMS connection and returns a kms.Service instance which can encrypt and decrypt data.
func newGoogleKMSService(cloud cloudprovider.Interface, rawConfig map[string]interface{}) (cloudprovider.KMSService, error) {
	var cloudkmsService *cloudkms.Service
	var cloudProjectID string

	// This check is false if cloud is nil, or is not an instance of gce.GCECloud.
	if gcp, ok := cloud.(*GCECloud); ok {
		// Hosting on GCE/GKE with Google KMS encryption provider
		cloudkmsService = gcp.GetKMSService()

		// cloudProjectID is the user's GCP project.
		cloudProjectID = gcp.GetProjectID()
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

	var config KMSConfig
	err := mapstructure.Decode(rawConfig, &config)
	if err != nil {
		return nil, err
	}

	// Set defaults for projectID, location and keyRing.
	if len(config.ProjectID) == 0 {
		config.ProjectID = cloudProjectID
	}
	if len(config.Location) == 0 {
		config.Location = "global"
	}
	if len(config.KeyRing) == 0 {
		config.KeyRing = defaultGKMSKeyRing
	}

	if len(config.ProjectID) == 0 {
		return nil, fmt.Errorf("missing projectID in encryption provider configuration for gkms provider")
	}
	if len(config.CryptoKey) == 0 {
		return nil, fmt.Errorf("missing cryptoKey in encryption provider configuration for gkms provider")
	}

	parentName := fmt.Sprintf("projects/%s/locations/%s", config.ProjectID, config.Location)

	// Create the keyRing if it does not exist yet
	_, err = cloudkmsService.Projects.Locations.KeyRings.Create(parentName,
		&cloudkms.KeyRing{}).KeyRingId(config.KeyRing).Do()
	if err != nil {
		apiError, isAPIError := err.(*googleapi.Error)
		// 409 means the keyRing exists.
		// 403 means we do not have permission to create the keyring, the user must do it.
		// Else, it is an unrecoverable error.
		if !isAPIError || (apiError.Code != 409 && apiError.Code != 403) {
			return nil, err
		}
	}
	parentName = parentName + "/keyRings/" + config.KeyRing

	// Create the cryptoKey if it does not exist yet
	_, err = cloudkmsService.Projects.Locations.KeyRings.CryptoKeys.Create(parentName,
		&cloudkms.CryptoKey{
			Purpose: "ENCRYPT_DECRYPT",
		}).CryptoKeyId(config.CryptoKey).Do()
	if err != nil {
		apiError, isAPIError := err.(*googleapi.Error)
		// 409 means the key exists.
		// 403 means we do not have permission to create the key, the user must do it.
		// Else, it is an unrecoverable error.
		if !isAPIError || (apiError.Code != 409 && apiError.Code != 403) {
			return nil, err
		}
	}
	parentName = parentName + "/cryptoKeys/" + config.CryptoKey

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
