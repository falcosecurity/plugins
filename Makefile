#
# Copyright (C) 2021 The Falco Authors.
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

SHELL := /bin/bash
GO ?= $(shell which go)
CURL = curl

FALCOSECURITY_LIBS_REVISION=e25e44b3ba4cb90ba9ac75bf747978e41fb6b221

OUTPUT_DIR := output
SOURCE_DIR := plugins
ARCH ?=$(shell uname -m)

plugins = $(shell ls -d ${SOURCE_DIR}/*/ | cut -f2 -d'/' | xargs)
plugins-clean = $(addprefix clean/,$(plugins))
plugins-packages = $(addprefix package/,$(plugins))

.PHONY: all
all: plugin_info.h $(plugins)

.PHONY: $(plugins)
$(plugins):
	cd plugins/$@ && make

.PHONY: clean
clean: clean/plugin_info.h $(plugins-clean) clean/packages clean/build/utils/version

.PHONY: clean/plugin_info.h
clean/plugin_info.h:
	rm -f plugin_info.h

.PHONY: clean/packages
clean/packages:
	rm -rf ${OUTPUT_DIR}

.PHONY: $(plugins-clean)
$(plugins-clean):
	cd plugins/$(shell basename $@) && make clean

.PHONY: packages
packages: clean/packages $(plugins-clean) $(plugins-packages)

.PHONY: $(plugins-packages)
$(plugins-packages): all build/utils/version
	$(eval PLUGIN_NAME := $(shell basename $@))
	$(eval PLUGIN_PATH := plugins/$(PLUGIN_NAME)/lib$(PLUGIN_NAME).so)
	$(eval PLUGIN_VERSION := $(shell ./build/utils/version --path $(PLUGIN_PATH) --pre-release | tail -n 1))
	echo $(PLUGIN_VERSION)

# re-run command to stop in case of non-zero exit code 
	@./build/utils/version --path $(PLUGIN_PATH) --pre-release > /dev/null

	mkdir -p $(OUTPUT_DIR)/$(PLUGIN_NAME)
	cp -r $(PLUGIN_PATH) $(OUTPUT_DIR)/$(PLUGIN_NAME)/
	cp -r plugins/$(PLUGIN_NAME)/README.md $(OUTPUT_DIR)/$(PLUGIN_NAME)/
	tar -zcvf $(OUTPUT_DIR)/$(PLUGIN_NAME)-$(PLUGIN_VERSION)-${ARCH}.tar.gz -C ${OUTPUT_DIR}/$(PLUGIN_NAME) .

.PHONY: plugin_info.h
plugin_info.h:
	$(CURL) -Lso $@ https://raw.githubusercontent.com/falcosecurity/libs/${FALCOSECURITY_LIBS_REVISION}/userspace/libscap/plugin_info.h

.PHONY: build/utils/version
build/utils/version:
	@cd build/utils && make

.PHONY: clean/build/utils/version
clean/build/utils/version:
	@cd build/utils && make clean