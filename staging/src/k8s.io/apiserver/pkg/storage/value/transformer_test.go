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
	"testing"
)

type testTransformer struct {
	from, to                 []byte
	err                      error
	stale                    bool
	receivedFrom, receivedTo []byte
}

func (t *testTransformer) TransformFromStorage(from []byte, context Context) (data []byte, stale bool, err error) {
	t.receivedFrom = from
	return t.from, t.stale, t.err
}

func (t *testTransformer) TransformToStorage(to []byte, context Context) (data []byte, err error) {
	t.receivedTo = to
	return t.to, t.err
}

func TestPrefixFrom(t *testing.T) {
	testErr := fmt.Errorf("test error")
	transformErr := fmt.Errorf("transform error")
	transformers := []PrefixTransformer{
		{Prefix: []byte("first:"), Transformer: &testTransformer{from: []byte("value1")}},
		{Prefix: []byte("second:"), Transformer: &testTransformer{from: []byte("value2")}},
		{Prefix: []byte("fails:"), Transformer: &testTransformer{err: transformErr}},
		{Prefix: []byte("stale:"), Transformer: &testTransformer{from: []byte("value3"), stale: true}},
	}
	p := NewPrefixTransformers(testErr, transformers...)

	testCases := []struct {
		input  []byte
		expect []byte
		stale  bool
		err    error
		match  int
	}{
		{[]byte("first:value"), []byte("value1"), false, nil, 0},
		{[]byte("second:value"), []byte("value2"), true, nil, 1},
		{[]byte("third:value"), nil, false, testErr, -1},
		{[]byte("fails:value"), nil, true, transformErr, 2},
		{[]byte("stale:value"), []byte("value3"), true, nil, 3},
	}
	for i, test := range testCases {
		got, stale, err := p.TransformFromStorage(test.input, nil)
		if err != test.err || stale != test.stale || !bytes.Equal(got, test.expect) {
			t.Errorf("%d: unexpected out: %q %t %#v", i, string(got), stale, err)
			continue
		}
		if test.match != -1 && !bytes.Equal([]byte("value"), transformers[test.match].Transformer.(*testTransformer).receivedFrom) {
			t.Errorf("%d: unexpected value received by transformer: %s", i, transformers[test.match].Transformer.(*testTransformer).receivedFrom)
		}
	}
}

func TestPrefixTo(t *testing.T) {
	testErr := fmt.Errorf("test error")
	transformErr := fmt.Errorf("transform error")
	testCases := []struct {
		transformers []PrefixTransformer
		expect       []byte
		err          error
	}{
		{[]PrefixTransformer{{Prefix: []byte("first:"), Transformer: &testTransformer{to: []byte("value1")}}}, []byte("first:value1"), nil},
		{[]PrefixTransformer{{Prefix: []byte("second:"), Transformer: &testTransformer{to: []byte("value2")}}}, []byte("second:value2"), nil},
		{[]PrefixTransformer{{Prefix: []byte("fails:"), Transformer: &testTransformer{err: transformErr}}}, nil, transformErr},
	}
	for i, test := range testCases {
		p := NewPrefixTransformers(testErr, test.transformers...)
		got, err := p.TransformToStorage([]byte("value"), nil)
		if err != test.err || !bytes.Equal(got, test.expect) {
			t.Errorf("%d: unexpected out: %q %#v", i, string(got), err)
			continue
		}
		if !bytes.Equal([]byte("value"), test.transformers[0].Transformer.(*testTransformer).receivedTo) {
			t.Errorf("%d: unexpected value received by transformer: %s", i, test.transformers[0].Transformer.(*testTransformer).receivedTo)
		}
	}
}

func TestLocationFrom(t *testing.T) {
	testErr := fmt.Errorf("test error")
	transformErr := fmt.Errorf("transform error")
	transformers := []LocationTransformer{
		{Location: "/first/", Transformer: &testTransformer{from: []byte("value0")}},
		{Location: "/first/second/", Transformer: &testTransformer{err: transformErr}},
		{Location: "/first/second/", Transformer: &testTransformer{from: []byte("value2")}},
		{Location: "/first/second/third/", Transformer: &testTransformer{from: []byte("value3")}},
	}
	p := NewLocationTransformers(testErr, transformers...)

	testCases := []struct {
		location string
		expect   []byte
		stale    bool
		err      error
		match    int
	}{
		{"/first/fourth/", []byte("value0"), false, nil, 0},
		{"/first/second/", []byte("value2"), false, nil, 2},
		{"/first/second/third/", []byte("value3"), false, nil, 3},
		{"/fifth/", nil, false, transformErr, -1},
	}
	for i, test := range testCases {
		got, stale, err := p.TransformFromStorage([]byte("value"), DefaultContext(test.location))
		if stale != test.stale || !bytes.Equal(got, test.expect) {
			t.Errorf("%d: unexpected out: %q %t %#v", i, string(got), stale, err)
			continue
		}
		if test.match != -1 && !bytes.Equal([]byte("value"), transformers[test.match].Transformer.(*testTransformer).receivedFrom) {
			t.Errorf("%d: unexpected value received by transformer: %s", i, transformers[test.match].Transformer.(*testTransformer).receivedFrom)
		}
	}
}

func TestLocationTo(t *testing.T) {
	testErr := fmt.Errorf("test error")
	transformErr := fmt.Errorf("transform error")
	transformers := []LocationTransformer{
		{Location: "/first/", Transformer: &testTransformer{to: []byte("value0")}},
		{Location: "/first/second/", Transformer: &testTransformer{to: []byte("value1")}},
		{Location: "/first/second/", Transformer: &testTransformer{to: []byte("value2")}},
		{Location: "/first/second/third/", Transformer: &testTransformer{to: []byte("value3")}},
		{Location: "/sixth/", Transformer: &testTransformer{err: transformErr}},
	}
	testCases := []struct {
		location string
		expect   []byte
		err      error
	}{
		{"/first", []byte("value0"), nil},
		{"/first/second/fifth/", []byte("value1"), nil},
		{"/first/second/third/fourth/", []byte("value3"), nil},
		{"/sixth/seventh", nil, transformErr},
	}
	for i, test := range testCases {
		p := NewLocationTransformers(testErr, transformers...)
		got, err := p.TransformToStorage([]byte("value"), DefaultContext(test.location))
		if err != test.err || !bytes.Equal(got, test.expect) {
			t.Errorf("%d: unexpected out: %q %#v", i, string(got), err)
			continue
		}
		if !bytes.Equal([]byte("value"), transformers[0].Transformer.(*testTransformer).receivedTo) {
			t.Errorf("%d: unexpected value received by transformer: %s", i, transformers[0].Transformer.(*testTransformer).receivedTo)
		}
	}
}
