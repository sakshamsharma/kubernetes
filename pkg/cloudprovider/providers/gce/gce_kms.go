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
	"strconv"
	"strings"

	"github.com/mitchellh/mapstructure"

	"golang.org/x/oauth2/google"
	cloudkms "google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/googleapi"
	"k8s.io/apiserver/pkg/storage/value/encrypt/kms"
	"k8s.io/kubernetes/pkg/cloudprovider"
)

const (
	KMSServiceName = "google-cloudkms"

	defaultGKMSKeyRing     = "google-kubernetes"
	delayBetweenKeyRefresh = 60
)

// GKMSConfig contains the GCE specific KMS configuration for setting up a KMS service.
type GKMSConfig struct {
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
		func(cloud cloudprovider.Interface, config map[string]interface{}) (kms.Service, error) {
			return newGoogleKMSService(cloud, config)
		})
}

// gkmsService provides Encrypt and Decrypt methods which allow cryptographic operations
// using Google Cloud KMS service.
type gkmsService struct {
	parentName      string
	cloudkmsService *cloudkms.Service

	// latestKeyVersion allows the transformer to identify stale data while reading.
	latestKeyVersion int64
}

// newGoogleKMSService creates a Google KMS connection and returns a kms.Service instance which can encrypt and decrypt data.
func newGoogleKMSService(cloud cloudprovider.Interface, rawConfig map[string]interface{}) (kms.Service, error) {
	var cloudkmsService *cloudkms.Service
	var cloudProjectID string

	// This check is false if cloud is nil, or is not an instance of gce.GCECloud.
	if gke, ok := cloud.(*GCECloud); ok {
		// Hosting on GCE/GKE with Google KMS encryption provider
		cloudkmsService = gke.GetKMSService()

		// Project ID is assumed to be the user's project unless there
		// is an override in the configuration file. If there is an override,
		// it will be taken into account by the Google KMS service constructor,
		// after reading the configuration file.
		cloudProjectID = gke.GetProjectID()
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

	var config GKMSConfig
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
		parentName:       parentName,
		cloudkmsService:  cloudkmsService,
		latestKeyVersion: 0,
	}

	// Sanity check before startup. For non-GCP clusters, the user's account may not have permissions to create
	// the key. We need to verify the existence of the key before apiserver startup.
	_, err = service.Encrypt([]byte("test"))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data using Google cloudkms, using key %s. Ensure that the keyRing and cryptoKey exist. Got error: %v", parentName, err)
	}

	return service, nil
}

// Decrypt decrypts a base64 representation of encrypted bytes, which has a key version prepended to the start.
func (t *gkmsService) Decrypt(data string) ([]byte, error) {
	dataChunks := strings.SplitN(data, ":", 2)
	if len(dataChunks) != 2 {
		return []byte{}, fmt.Errorf("invalid data encountered for decryption: %s. Missing key version", data)
	}

	resp, err := t.cloudkmsService.Projects.Locations.KeyRings.CryptoKeys.
		Decrypt(t.parentName, &cloudkms.DecryptRequest{
			Ciphertext: dataChunks[1],
		}).Do()
	if err != nil {
		apiError, ok := err.(*googleapi.Error)
		// If it was a 400, we can try to check if the key was scheduled for deletion, and restore it.
		if !ok || apiError.Code != 400 {
			return nil, err
		}

		// Recover the key if possible, and enable it.
		recoverErr := t.recoverKeyVersion(dataChunks[0])
		if recoverErr != nil {
			return nil, fmt.Errorf("%v. Could not recover key too: %v", err, recoverErr)
		}

		// Try decrypting once again
		resp, err = t.cloudkmsService.Projects.Locations.KeyRings.CryptoKeys.
			Decrypt(t.parentName, &cloudkms.DecryptRequest{
				Ciphertext: dataChunks[1],
			}).Do()
		if err != nil {
			return nil, err
		}
	}
	return base64.StdEncoding.DecodeString(resp.Plaintext)
}

// Encrypt encrypts bytes, and returns base64 representation of the ciphertext, prepended with the key version.
func (t *gkmsService) Encrypt(data []byte) (string, error) {
	resp, err := t.cloudkmsService.Projects.Locations.KeyRings.CryptoKeys.
		Encrypt(t.parentName, &cloudkms.EncryptRequest{
			Plaintext: base64.StdEncoding.EncodeToString(data),
		}).Do()
	if err != nil {
		return "", err
	}

	keyVersion, err := getKeyVersionFromName(resp.Name)
	if err != nil {
		return "", err
	}
	if keyVersion > t.latestKeyVersion {
		t.latestKeyVersion = keyVersion
	}

	// Prepend the key version (integer) to the string
	return (strconv.Itoa(int(keyVersion)) + ":" + resp.Ciphertext), nil
}

// CheckStale checks if the provided encrypted text is stale and needs to be re-encrypted.
func (t *gkmsService) CheckStale(data string) (bool, error) {
	if t.latestKeyVersion == 0 {
		// Not yet initialized
		return false, nil
	}
	dataChunks := strings.SplitN(data, ":", 2)
	if len(dataChunks) != 2 {
		return false, fmt.Errorf("invalid data encountered during stale check: %s. Missing key version", data)
	}
	keyVersion, err := strconv.ParseInt(dataChunks[0], 10, 64)
	if err != nil {
		return false, fmt.Errorf("invalid key version encountered during stale check: %s", dataChunks[0])
	}
	return (keyVersion < t.latestKeyVersion), nil
}

// recoverKeyVersion tries to recover and enable key versions scheduled for deletion. This is called
// when some data encrypted by the old key is encountered.
func (t *gkmsService) recoverKeyVersion(keyVersion string) error {
	cryptoKeyVersionObj, err := t.cloudkmsService.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
		Get(t.parentName + "/cryptoKeyVersions/" + keyVersion).Do()
	if err != nil {
		// Cannot handle this error
		return err
	}
	if cryptoKeyVersionObj.State == "DESTROY_SCHEDULED" {
		// Ignore error in this. Some other master may already have called this in parallel.
		t.cloudkmsService.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
			Restore(t.parentName+"/cryptoKeyVersions/"+keyVersion, &cloudkms.RestoreCryptoKeyVersionRequest{}).Do()
	}

	// It may have been disabled to begin with, or may have been put in disabled state after restoration.
	if cryptoKeyVersionObj.State == "DISABLED" || cryptoKeyVersionObj.State == "DESTROY_SCHEDULED" {
		// Ignore error in this. Some other master may already have called this in parallel.
		t.cloudkmsService.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
			Patch(t.parentName+"/cryptoKeyVersions/"+keyVersion, &cloudkms.CryptoKeyVersion{
				State: "ENABLED",
			}).UpdateMask("state").Do()
	}
	return nil
}

// getKeyVersionFromName parses the key version from the provided full path of the key,
// as returned by cloudkms API.
func getKeyVersionFromName(name string) (int64, error) {
	// KeyName looks like:
	// projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*
	keyNameChunks := strings.SplitN(name, "/", 10)
	// Only handle the case when there are no errors because this operation runs periodically.
	// TODO(sakshams): Print errors as warning if something fails.
	if len(keyNameChunks) != 10 {
		return 0, fmt.Errorf("invalid key name returned from Google KMS: %s", name)
	}
	keyVersion, err := strconv.ParseInt(keyNameChunks[9], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid key version returned from Google KMS: %s. Error: %s", keyNameChunks[9], err)
	}
	return keyVersion, nil
}
