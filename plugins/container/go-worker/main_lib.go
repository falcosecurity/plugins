//go:build !exe

package main

func main() {
	// Noop, required to make CGO happy: `-buildmode=c-*` requires exactly one
	// main package, which in turn needs a `main` function`.
}
