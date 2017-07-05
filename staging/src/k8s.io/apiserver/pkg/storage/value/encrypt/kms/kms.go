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

// Package kms transforms values for storage at rest using a KMS provider
package kms

import (
	"fmt"
	"sync"

	"k8s.io/apiserver/pkg/storage/value"

	lru "github.com/hashicorp/golang-lru"
)

type kmsTransformer struct {
	kmsService   value.KMSService
	transformers *lru.Cache

	// cacheSize is the maximum number of DEKs that are cached.
	cacheSize int

	lock sync.RWMutex
}

// NewKMSTransformer returns a transformer which implements a KEK-DEK based envelope encryption scheme.
// It uses kmsService to communicate with the KEK store, and storage to communicate with the DEK store.
func NewKMSTransformer(kmsService value.KMSService, cacheSize int) (value.Transformer, error) {
	return nil, fmt.Errorf("not yet implemented")
}
