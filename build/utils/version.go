//go:build (linux && cgo) || (darwin && cgo) || (freebsd && cgo)
// +build linux,cgo darwin,cgo freebsd,cgo

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
)

/*
#cgo linux LDFLAGS: -ldl
#include <dlfcn.h>
#include <limits.h>
#include <stdlib.h>
#include <stdint.h>

#include <stdio.h>

static uintptr_t pluginOpen(const char* path, char** err) {
	void* h = dlopen(path, RTLD_NOW|RTLD_GLOBAL);
	if (h == NULL) {
		*err = (char*)dlerror();
	}
	return (uintptr_t)h;
}

static char* get_name(uintptr_t h, char** err) {
	void* s = dlsym((void*)h, "plugin_get_name");
	if (s == NULL) {
		*err = (char*)dlerror();
        return NULL;
	}
	typedef char* (*fptr)();
    fptr f = (fptr)s;
    return f();
}

static char* get_version(uintptr_t h, char** err) {
	void* s = dlsym((void*)h, "plugin_get_version");
	if (s == NULL) {
		*err = (char*)dlerror();
        return NULL;
	}
	typedef char* (*fptr)();
    fptr f = (fptr)s;
    return f();
}

*/
import "C"

func pluginInfo(path string) (name, version string, err error) {
	path, err = filepath.Abs(path)
	if err != nil {
		return
	}

	cPath := C.CString(path)
	var cErr *C.char

	h := C.pluginOpen(cPath, &cErr)
	if h == 0 {
		err = errors.New("cannot open " + path + ": " + C.GoString(cErr))
		return
	}

	cName := C.get_name(h, &cErr)
	if cName == nil {
		err = errors.New("cannot get name of " + path + ": " + C.GoString(cErr))
		return
	}

	cVer := C.get_version(h, &cErr)
	if cVer == nil {
		err = errors.New("cannot get version of " + path + ": " + C.GoString(cErr))
		return
	}

	return C.GoString(cName), C.GoString(cVer), nil
}

func git(args ...string) (output []string, err error) {
	fmt.Println("git ", strings.Join(args, " "))
	stdout, err := exec.Command("git", args...).Output()
	fmt.Println(string(stdout))
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, errors.New("git (" + exitErr.String() + "): " + string(exitErr.Stderr))
		}
		return nil, err
	}

	return strings.Split(string(stdout), "\n"), nil
}

func fail(err error) {
	fmt.Printf("error: %s\n", err)
	os.Exit(1)
}

func main() {
	var path string
	var pre bool
	pflag.StringVar(&path, "path", "", "path to the .so file")
	pflag.BoolVar(&pre, "pre-release", false, "if set, output a pre-release version")
	pflag.Parse()

	name, version, err := pluginInfo(path)
	if err != nil {
		fail(err)
	}

	// fmt.Println(name)
	// fmt.Println(version)

	if pre {
		// pre-releases MUST adhere to x.y.z-a.b.c-n+hash format, given:
		// - x.y.z is the plugin declared version
		// - a.b.c is the latest released version of the plugin (git tagged)
		// - n is the numeber of commits since the latest released version
		// - hash is the git commit id (abbrev to 7 digits)

		lastVer := "0.0.0" // fallback value
		var n int
		var hash string

		// get last tag
		tags, err := git("describe", "--tags", "--abbrev=0", "--match", name+`-*`)
		if err == nil {
			if len(tags) == 0 {
				fail(errors.New("no git tag found for: " + name))
			}
			lastTag := tags[0]
			lastVer = strings.Replace(lastTag, name+"-", "", 1)

			// get number of commits since the last tag
			counts, err := git("rev-list", lastTag+"..", "--count")
			if err != nil {
				fail(err)
			}
			if len(counts) > 0 {
				n, _ = strconv.Atoi(counts[0])
			}
		}

		refs, err := git("rev-parse", "--short=7", "HEAD")
		if err != nil {
			fail(err)
		}
		if len(refs) == 0 {
			fail(errors.New("no commit id found"))
		}
		hash = refs[0]

		fmt.Printf("%s-%s-%d+%s\n", version, lastVer, n, hash)

	} else {
		// stable versions MUST have a precise tag matching plugin name and version
		expectedTag := name + "-" + version
		tags, err := git("--no-pager", "tag", "--points-at", "HEAD")
		if err != nil {
			fail(err)
		}
		for _, tag := range tags {
			if tag == expectedTag {
				fmt.Println(version)
				return
			}
		}

		fail(errors.New("no git tag found: " + expectedTag))
	}

}
