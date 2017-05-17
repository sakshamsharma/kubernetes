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

package toy

import (
	"encoding/base64"

	"k8s.io/apiserver/pkg/storage/value"
)

type toy struct {
}

func (t *toy) TransformFromStorage(data []byte, context value.Context) ([]byte, bool, error) {
	a, err := base64.StdEncoding.DecodeString(string(data))
	return a, false, err
}

func (t *toy) TransformToStorage(data []byte, context value.Context) ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(data)), nil
}

var ToyTransformer value.Transformer = &toy{}
