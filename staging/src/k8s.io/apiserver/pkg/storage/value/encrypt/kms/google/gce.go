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
	"context"
	"net/http"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"

	gcfg "gopkg.in/gcfg.v1"

	"github.com/golang/glog"

	"cloud.google.com/go/compute/metadata"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	cloudkms "google.golang.org/api/cloudkms/v1"
	compute "google.golang.org/api/compute/v1"
)

type CloudkmsService struct {
	CloudkmsService *cloudkms.Service
	ProjectID       string
}

// Has to be the same as the configuration available in the GCE cloudprovider.
// Currently at k8s.io/kubernetes/pkg/cloudprovider/providers/gce.
// Although only the first 3 fields are needed, gcfg does not parse the configuration
// if there are extra elements in the actual file. Which is why, we need to keep all the
// fields here.
type cloudConfig struct {
	Global struct {
		TokenURL           string   `gcfg:"token-url"`
		TokenBody          string   `gcfg:"token-body"`
		ProjectID          string   `gcfg:"project-id"`
		NetworkName        string   `gcfg:"network-name"`
		SubnetworkName     string   `gcfg:"subnetwork-name"`
		NodeTags           []string `gcfg:"node-tags"`
		NodeInstancePrefix string   `gcfg:"node-instance-prefix"`
		Multizone          bool     `gcfg:"multizone"`
		ApiEndpoint        string   `gcfg:"api-endpoint"`
	}
}

// InitCloudkmsService creates a CloudkmsService object containing the GCP ProjectID
// (if available), and the cloudkmsService object.
func InitCloudkmsService(name string, configFilePath string) (*CloudkmsService, error) {
	cloud := &CloudkmsService{}

	if name == "gce" && configFilePath != "" {
		projectID, err := metadata.ProjectID()
		if err != nil {
			return nil, err
		}

		tokenSource := google.ComputeTokenSource("")

		var cfg cloudConfig
		if err := gcfg.ReadFileInto(&cfg, configFilePath); err != nil {
			glog.Errorf("Couldn't read config: %v", err)
			return nil, err
		}
		glog.Infof("Using GCE provider config %+v", cfg)

		if cfg.Global.ProjectID != "" {
			projectID = cfg.Global.ProjectID
		}
		if cfg.Global.TokenURL != "" {
			tokenSource = NewAltTokenSource(cfg.Global.TokenURL, cfg.Global.TokenBody)
		}

		client, err := newOauthClient(tokenSource)
		if err != nil {
			return nil, err
		}
		cloudkmsService, err := cloudkms.New(client)
		if err != nil {
			return nil, err
		}

		cloud = &CloudkmsService{
			CloudkmsService: cloudkmsService,
			ProjectID:       projectID,
		}
	} else {
		// Outside GCE/GKE, or no cloud configuration provided by cloud.
		// Requires GOOGLE_APPLICATION_CREDENTIALS environment variable.
		// This describes how that can be done:
		// https://developers.google.com/identity/protocols/application-default-credentials
		ctx := context.Background()
		client, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
		if err != nil {
			return nil, err
		}
		cloud.CloudkmsService, err = cloudkms.New(client)
		if err != nil {
			return nil, err
		}
		cloud.ProjectID = ""
	}
	return cloud, nil
}

// newOauthClient provides an http client for cloud, given a token source.
// It has been copied from GCE cloudprovider.
func newOauthClient(tokenSource oauth2.TokenSource) (*http.Client, error) {
	if tokenSource == nil {
		var err error
		tokenSource, err = google.DefaultTokenSource(
			oauth2.NoContext,
			compute.CloudPlatformScope,
			compute.ComputeScope)
		glog.Infof("Using DefaultTokenSource %#v", tokenSource)
		if err != nil {
			return nil, err
		}
	} else {
		glog.Infof("Using existing Token Source %#v", tokenSource)
	}

	if err := wait.PollImmediate(5*time.Second, 30*time.Second, func() (bool, error) {
		if _, err := tokenSource.Token(); err != nil {
			glog.Errorf("error fetching initial token: %v", err)
			return false, nil
		}
		return true, nil
	}); err != nil {
		return nil, err
	}

	return oauth2.NewClient(oauth2.NoContext, tokenSource), nil
}
