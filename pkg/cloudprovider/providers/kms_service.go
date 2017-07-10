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
	"fmt"

	"golang.org/x/oauth2/google"

	cloudkms "google.golang.org/api/cloudkms/v1"
	"k8s.io/apiserver/pkg/storage/value/encrypt/kms"
	"k8s.io/kubernetes/pkg/cloudprovider"
	"k8s.io/kubernetes/pkg/cloudprovider/providers/gce"
)

type kmsServiceFactory struct {
	cloudName      string
	configFilePath string
}

// NewKMSServiceFactory creates a CloudKMSServiceFactory which can provide various cloud KMS services.
func NewKMSServiceFactory(name, configFilePath string) kms.CloudKMSServiceFactory {
	return &kmsServiceFactory{
		cloudName:      name,
		configFilePath: configFilePath,
	}
}

func (k *kmsServiceFactory) GetGoogleKMSService() (*cloudkms.Service, string, error) {
	cloud, err := cloudprovider.InitCloudProvider(k.cloudName, k.configFilePath)
	if err != nil {
		return nil, "", fmt.Errorf("cloud provider could not be initialized: %v", err)
	}

	var cloudkmsService *cloudkms.Service
	var projectID string

	// This check is false if cloud is nil, or is not an instance of gce.GCECloud.
	if gke, ok := cloud.(*gce.GCECloud); ok {
		// Hosting on GCE/GKE with Google KMS encryption provider
		cloudkmsService = gke.GetKMSService()

		// Project ID is assumed to be the user's project unless there
		// is an override in the configuration file. If there is an override,
		// it will be taken into account by the Google KMS service constructor,
		// after reading the configuration file.
		projectID = gke.ProjectID()
	} else {
		// When running outside GCE/GKE and connecting to KMS, GOOGLE_APPLICATION_CREDENTIALS
		// environment variable is required. This describes how that can be done:
		// https://developers.google.com/identity/protocols/application-default-credentials
		ctx := context.Background()
		client, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
		if err != nil {
			return nil, "", err
		}
		cloudkmsService, err = cloudkms.New(client)
		if err != nil {
			return nil, "", err
		}
		projectID = ""
	}
	return cloudkmsService, projectID, nil
}
