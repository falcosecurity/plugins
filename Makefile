# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
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

DEBUG = 1
PRE_RELEASE = --pre-release
OUTPUT_DIR := output
SOURCE_DIR := plugins
ARCH ?=$(shell uname -m)
PLATFORM ?=$(shell uname -s | tr '[:upper:]' '[:lower:]')

plugins = $(shell ls -d ${SOURCE_DIR}/*/ | cut -f2 -d'/' | xargs)
plugins-clean = $(addprefix clean/,$(plugins))
plugins-changelogs = $(addprefix changelog/,$(plugins))
plugins-packages = $(addprefix package/,$(plugins))
plugins-releases = $(addprefix release/,$(plugins))

.PHONY: all
all: check-registry $(plugins)

.PHONY: $(plugins)
$(plugins): build/readme/readme
	+cd plugins/$@ && make DEBUG=$(DEBUG)
# make rules, if any
	+@cd plugins/$@ \
		&& make rules \
		&& echo "$@ rules generated" || :
# make readme, if any
	+@cd plugins/$@ \
		&& make readme READMETOOL=../../build/readme/bin/readme \
		&& echo "$@ readme generated" || :

.PHONY: clean
clean: $(plugins-clean) clean/packages clean/build/utils/version clean/build/registry/registry clean/build/changelog/changelog clean/build/readme/readme

.PHONY: clean/packages
clean/packages:
	rm -rf ${OUTPUT_DIR}

.PHONY: $(plugins-clean)
$(plugins-clean):
	+cd plugins/$(shell basename $@) && make clean

.PHONY: packages
packages: clean/packages $(plugins-packages)

package/%: clean/% % build/utils/version
	$(eval PLUGIN_NAME := $(shell basename $@))
	$(eval PLUGIN_PATH := plugins/$(PLUGIN_NAME)/lib$(PLUGIN_NAME).so)
	$(eval PLUGIN_VERSION := $(shell ./build/utils/version --path $(PLUGIN_PATH) $(PRE_RELEASE) | tail -n 1))
# re-run command to stop in case of non-zero exit code 
	@./build/utils/version --path $(PLUGIN_PATH) $(PRE_RELEASE)
	mkdir -p $(OUTPUT_DIR)/$(PLUGIN_NAME)
	cp -r $(PLUGIN_PATH) $(OUTPUT_DIR)/$(PLUGIN_NAME)/
	tar -zcvf $(OUTPUT_DIR)/$(PLUGIN_NAME)-$(PLUGIN_VERSION)-${PLATFORM}-${ARCH}.tar.gz -C ${OUTPUT_DIR}/$(PLUGIN_NAME) $$(ls -A ${OUTPUT_DIR}/$(PLUGIN_NAME))
	rm -rf $(OUTPUT_DIR)/$(PLUGIN_NAME)
	@echo "$(PLUGIN_NAME) package built"
# build rules package, if any
	mkdir -p $(OUTPUT_DIR)/$(PLUGIN_NAME)-rules
	# symlinks are ignored when creating the rules package. Only regular files are considered.
	find plugins/$(PLUGIN_NAME)/rules/* -type f -exec cp -t $(OUTPUT_DIR)/$(PLUGIN_NAME)-rules/ {} + && \
		tar -zcvf $(OUTPUT_DIR)/$(PLUGIN_NAME)-rules-$(PLUGIN_VERSION).tar.gz -C \
		$(OUTPUT_DIR)/$(PLUGIN_NAME)-rules $$(ls -A ${OUTPUT_DIR}/$(PLUGIN_NAME)-rules) || :
	@test $(OUTPUT_DIR)/$(PLUGIN_NAME)-rules-$(PLUGIN_VERSION).tar.gz && echo "$(PLUGIN_NAME) rules package built"
	rm -rf $(OUTPUT_DIR)/$(PLUGIN_NAME)-rules

release/%: DEBUG=0
release/%: PRE_RELEASE=
release/%: clean package/%
	@echo "$(PLUGIN_NAME) released"

.PHONY: changelogs
changelogs: $(plugins-changelogs)

changelog/%: build/changelog/changelog
	$(eval PLUGIN_NAME := $(shell basename $@))
	$(eval CHANGELOG_PATH := plugins/$(PLUGIN_NAME)/CHANGELOG.md)
	@./changelog-gen.sh $(PLUGIN_NAME) > $(CHANGELOG_PATH)
	@echo "$(CHANGELOG_PATH) generated"

.PHONY: check-registry
check-registry: build/registry/registry
	@build/registry/bin/registry check ./registry.yaml
	@echo The plugin registry is OK

.PHONY: update-readme
update-readme: build/registry/registry
	@build/registry/bin/registry table ./registry.yaml \
		--subfile=./README.md \
		--subtag="<!-- REGISTRY:TABLE -->"
	@echo Readme has been updated successfully

.PHONY: update-index
update-index: build/registry/registry
	@build/registry/bin/registry update-index ./registry.yaml ${DIST_INDEX}
	@echo Distribution index has been updated successfully

.PHONY: build/utils/version
build/utils/version:
	+@cd build/utils && make

.PHONY: clean/build/utils/version
clean/build/utils/version:
	+@cd build/utils && make clean

.PHONY: build/registry/registry
build/registry/registry:
	+@cd build/registry && make

.PHONY: clean/build/registry/registry
clean/build/registry/registry:
	+@cd build/registry && make clean

.PHONY: build/changelog/changelog
build/changelog/changelog:
	+@cd build/changelog && make

.PHONY: clean/build/changelog/changelog
clean/build/changelog/changelog:
	+@cd build/changelog && make clean

.PHONY: build/readme/readme
build/readme/readme:
	+@cd build/readme && make

.PHONY: clean/build/readme/readme
clean/build/readme/readme:
	+@cd build/readme && make clean
