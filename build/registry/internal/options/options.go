package options

import (
	"io"
)

type CommonOptions struct {
	Output io.Writer
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
