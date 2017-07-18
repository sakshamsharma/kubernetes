/*
Copyright 2014 The Kubernetes Authors.

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
	"fmt"
	"io"
	"os"
	"sync"

	"k8s.io/apiserver/pkg/storage/value/encrypt/kms"

	"github.com/golang/glog"
)

// Factory is a function that returns a cloudprovider.Interface.
// The config parameter provides an io.Reader handler to the factory in
// order to load specific configurations. If no configuration is provided
// the parameter is nil.
type Factory func(config io.Reader) (Interface, error)

// KMSServiceFactory is a function that returns a cloudprovider.kms.Service.
// The cloud parameter is a cloudprovider.Interface which can be used by the kms.Service.
// The config parameter provides the unstructured configuration specific
// to the KMS service provider.
type KMSServiceFactory func(cloud Interface, config map[string]interface{}) (kms.Service, error)

// All registered cloud providers and kms services.
var (
	providersMutex sync.Mutex
	providers      = make(map[string]Factory)

	kmsServicesMutex sync.Mutex
	kmsServices      = make(map[string]KMSServiceFactory)
)

const externalCloudProvider = "external"

// RegisterCloudProvider registers a cloudprovider.Factory by name.  This
// is expected to happen during app startup.
func RegisterCloudProvider(name string, cloud Factory) {
	providersMutex.Lock()
	defer providersMutex.Unlock()
	if _, found := providers[name]; found {
		glog.Fatalf("Cloud provider %q was registered twice", name)
	}
	glog.V(1).Infof("Registered cloud provider %q", name)
	providers[name] = cloud
}

// IsCloudProvider returns true if name corresponds to an already registered
// cloud provider.
func IsCloudProvider(name string) bool {
	providersMutex.Lock()
	defer providersMutex.Unlock()
	_, found := providers[name]
	return found
}

// CloudProviders returns the name of all registered cloud providers in a
// string slice
func CloudProviders() []string {
	names := []string{}
	providersMutex.Lock()
	defer providersMutex.Unlock()
	for name := range providers {
		names = append(names, name)
	}
	return names
}

// GetCloudProvider creates an instance of the named cloud provider, or nil if
// the name is unknown.  The error return is only used if the named provider
// was known but failed to initialize. The config parameter specifies the
// io.Reader handler of the configuration file for the cloud provider, or nil
// for no configuation.
func GetCloudProvider(name string, config io.Reader) (Interface, error) {
	providersMutex.Lock()
	defer providersMutex.Unlock()
	f, found := providers[name]
	if !found {
		return nil, nil
	}
	return f(config)
}

// Detects if the string is an external cloud provider
func IsExternal(name string) bool {
	return name == externalCloudProvider
}

// InitCloudProvider creates an instance of the named cloud provider.
func InitCloudProvider(name string, configFilePath string) (Interface, error) {
	var cloud Interface
	var err error

	if name == "" {
		glog.Info("No cloud provider specified.")
		return nil, nil
	}

	if IsExternal(name) {
		glog.Info("External cloud provider specified")
		return nil, nil
	}

	if configFilePath != "" {
		var config *os.File
		config, err = os.Open(configFilePath)
		if err != nil {
			glog.Fatalf("Couldn't open cloud provider configuration %s: %#v",
				configFilePath, err)
		}

		defer config.Close()
		cloud, err = GetCloudProvider(name, config)
	} else {
		// Pass explicit nil so plugins can actually check for nil. See
		// "Why is my nil error value not equal to nil?" in golang.org/doc/faq.
		cloud, err = GetCloudProvider(name, nil)
	}

	if err != nil {
		return nil, fmt.Errorf("could not init cloud provider %q: %v", name, err)
	}
	if cloud == nil {
		return nil, fmt.Errorf("unknown cloud provider %q", name)
	}

	return cloud, nil
}

// RegisterKMSService registers a kms.Service by name.  This
// is expected to happen during app startup.
// The name is provided in the encryption-provider-config file, under
// the property 'kind' in transformer configuration, and must match the
// KMSServiceName in one of the available KMS services.
func RegisterKMSService(name string, kmsService KMSServiceFactory) {
	kmsServicesMutex.Lock()
	defer kmsServicesMutex.Unlock()
	if _, found := kmsServices[name]; found {
		glog.Fatalf("KMS service %q was registered twice", name)
	}
	glog.V(1).Infof("Registered KMS service %q", name)
	kmsServices[name] = kmsService
}

// GetKMSService creates an instance of the named KMS service, or nil if
// the name is unknown.  The error return is only used if the named service
// was known but failed to initialize. The config parameter specifies the
// unstructured configuration specific to that provider.
func GetKMSService(name string, cloud Interface, config map[string]interface{}) (kms.Service, error) {
	kmsServicesMutex.Lock()
	defer kmsServicesMutex.Unlock()
	f, found := kmsServices[name]
	if !found {
		return nil, nil
	}
	return f(cloud, config)
}

// InitKMSService creates an instance of the named KMS service.
func InitKMSService(name string, configFilePath string, kmsName string, kmsConfig map[string]interface{}) (kms.Service, error) {
	cloud, err := InitCloudProvider(name, configFilePath)
	if err != nil {
		return nil, err
	}
	return GetKMSService(kmsName, cloud, kmsConfig)
}
