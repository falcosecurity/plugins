// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

package common

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExtractTarGz extracts a *.tar.gz compressed archive and moves its content to destDir.
// Returns a slice containing the full path of the extracted files.
func ExtractTarGz(fileName, destDir string) ([]string, error) {
	var files []string

	gzipStream, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("unable to open file %q: %w", fileName, err)
	}

	uncompressedStream, err := gzip.NewReader(gzipStream)
	if err != nil {
		return nil, err
	}

	tarReader := tar.NewReader(uncompressedStream)

	for {
		header, err := tarReader.Next()

		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return nil, err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			return nil, fmt.Errorf("unexepected dir inside the archive, expected to find only files without any tree structure")
		case tar.TypeReg, tar.TypeSymlink:
			f := filepath.Join(destDir, filepath.Clean(header.Name))
			if !strings.HasPrefix(f, filepath.Clean(destDir)+string(os.PathSeparator)) {
				return nil, fmt.Errorf("illegal file path: %q", f)
			}
			outFile, err := os.Create(filepath.Clean(f))
			if err != nil {
				return nil, err
			}
			if err = copyInChunks(outFile, tarReader); err != nil {
				return nil, err
			}
			if err = outFile.Close(); err != nil {
				return nil, err
			}
			files = append(files, f)

		default:
			return nil, fmt.Errorf("extractTarGz: uknown type: %b in %s", header.Typeflag, header.Name)
		}
	}

	return files, nil
}

func copyInChunks(dst io.Writer, src io.Reader) error {
	for {
		_, err := io.CopyN(dst, src, 1024)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
	}

	return nil
}
