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

// Package gms transforms values for storage at rest using Google KMS.
package gkms

import (
	"encoding/base64"
	"fmt"

	netcontext "golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	cloudkms "google.golang.org/api/cloudkms/v1"
	"k8s.io/apiserver/pkg/storage/value"
)

type gkmsTransformer struct {
	ParentName      string
	CloudkmsService *cloudkms.Service
}

func NewGoogleKMSTransformer(projectID, location, keyRing, cryptoKey string) (value.Transformer, error) {
	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		projectID, location, keyRing, cryptoKey)

	ctx := netcontext.Background()
	client, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	cloudkmsService, err := cloudkms.New(client)
	if err != nil {
		return nil, err
	}

	return &gkmsTransformer{parentName, cloudkmsService}, nil
}

func (t *gkmsTransformer) TransformFromStorage(data []byte, context value.Context) ([]byte, bool, error) {

	resp, err := t.CloudkmsService.Projects.Locations.KeyRings.CryptoKeys.
		Decrypt(t.ParentName, &cloudkms.DecryptRequest{
			Ciphertext: base64.StdEncoding.EncodeToString(data),
		}).Do()
	if err != nil {
		return nil, false, err
	}
	result, err := base64.StdEncoding.DecodeString(resp.Plaintext)
	return result, false, err
}

func (t *gkmsTransformer) TransformToStorage(data []byte, context value.Context) ([]byte, error) {
	resp, err := t.CloudkmsService.Projects.Locations.KeyRings.CryptoKeys.
		Encrypt(t.ParentName, &cloudkms.EncryptRequest{
			Plaintext: base64.StdEncoding.EncodeToString(data),
		}).Do()
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(resp.Ciphertext)
}
