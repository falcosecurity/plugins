/*
Copyright (C) 2022 The Falco Authors.

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

package options

import (
	"context"
	"io"
)

type CommonOptions struct {
	Output  io.Writer
	Context context.Context
}

type CommonOption func(opts *CommonOptions)

func NewCommonOptions(opts ...CommonOption) *CommonOptions {
	o := &CommonOptions{}

	for _, f := range opts {
		f(o)
	}

	return o
}

func WithOutput(out io.Writer) CommonOption {
	return func(opts *CommonOptions) {
		opts.Output = out
	}
}

func WithContext(ctx context.Context) CommonOption {
	return func(opts *CommonOptions) {
		opts.Context = ctx
	}
}
