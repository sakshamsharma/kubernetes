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

package value

import (
	"bytes"
	"fmt"
)

// LocationTransformer holds a transformer interface and the location of the resources it has to be used for.
type LocationTransformer struct {
	Location    string
	Transformer Transformer
}

type locationTransformers struct {
	transformers []LocationTransformer
	err          error
}

var _ Transformer = &locationTransformers{}

// NewLocationTransformers supports the Transformer interface by first filtering transformers on
// whether they are configured to write to the given location. This is done by detecting which transformer's
// location is a prefix of this resource's location, and choosing the most specific of those locations.
func NewLocationTransformers(err error, transformers ...LocationTransformer) Transformer {
	if err == nil {
		err = fmt.Errorf("the provided value not match any of the supported transformers")
	}
	return &locationTransformers{
		transformers: transformers,
		err:          err,
	}
}

// TransformFromStorage collects all possible transformers (based on their location parameter) and
// attempts to decrypt using each of them
func (t *locationTransformers) TransformFromStorage(data []byte, context Context) ([]byte, bool, error) {
	for _, transformerID := range t.longestMatchingTransformers(context) {
		result, stale, err := t.transformers[transformerID].Transformer.TransformFromStorage(data, context)
		if err == nil {
			return result, stale, err
		}
	}
	return nil, false, t.err
}

// TransformToStorage finds the first transformer which was configured to write to the location
// stored in context, and transforms data using that.
func (t *locationTransformers) TransformToStorage(data []byte, context Context) ([]byte, error) {
	transformerToUse := t.longestMatchingTransformers(context)

	// If no transformer was assigned to the given location, do not encrypt the data
	if len(transformerToUse) == 0 {
		return data, nil
	}

	// Else use the first matching transformer to write the value to disk.
	return t.transformers[transformerToUse[0]].Transformer.TransformToStorage(data, context)
}

// Returns the indices of the transformers which have their location as a prefix of the context, and
// are the ones with the longest such matching prefix, in a single pass.
func (t *locationTransformers) longestMatchingTransformers(context Context) []int {
	var ts []int
	maxMatch := 0
	strToMatch := context.AuthenticatedData()
	if !bytes.HasSuffix(strToMatch, []byte("/")) {
		strToMatch = append(strToMatch, byte('/'))
	}
	for i, transformer := range t.transformers {
		if bytes.HasPrefix(strToMatch, []byte(transformer.Location)) {
			length := len(transformer.Location)
			if length > maxMatch {
				maxMatch = length
				ts = []int{i}
			} else if length == maxMatch {
				ts = append(ts, i)
			}
		}
	}
	return ts
}
