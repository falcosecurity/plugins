#
# Copyright (C) 2022 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#

SHELL=/bin/bash -o pipefail
GO ?= $(shell which go)
CURL ?= $(shell which curl)

FALCOSECURITY_LIBS_REPO ?= falcosecurity/libs
FALCOSECURITY_LIBS_REVISION ?= a188028bbaa759636cc46a7c59bcb805195ae974

PLUGIN_INFO_DIR=pkg/loader
PLUGIN_INFO_URL=https://raw.githubusercontent.com/${FALCOSECURITY_LIBS_REPO}/${FALCOSECURITY_LIBS_REVISION}/userspace/libscap/plugin_info.h

.PHONY: all
all: version

$(PLUGIN_INFO_DIR)/plugin_info.h:
	@echo Downloading $(PLUGIN_INFO_URL)...
	$(CURL) -Lso $(PLUGIN_INFO_DIR)/plugin_info.h $(PLUGIN_INFO_URL)


test/sample/libsample.so:
	@$(GO) build -buildmode=c-shared -o test/sample/libsample.so ./test/sample/...

.PHONY: clean
clean:
	@rm -fr bin $(PLUGIN_INFO_DIR)/plugin_info.h

.PHONY: test
test: test/sample/libsample.so
	@$(GO) test ./...

.PHONY: version
version: $(PLUGIN_INFO_DIR)/plugin_info.h
	@mkdir -p bin
	@$(GO) build -o bin/version ./cmd/version/...

