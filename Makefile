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

FALCOSECURITY_LIBS_REVISION=new/plugin-system-api-additions

PLUGINS_VERSION=$(shell git describe --always --tags)
KERNEL=$(shell uname -s | tr A-Z a-z)
ARCH=$(shell uname -m)
PACKAGE_DIR=falcosecurity-plugins-${PLUGINS_VERSION}-${KERNEL}-${ARCH}

plugins = cloudtrail dummy dummy_c json
pluginsclean = $(addsuffix clean,$(plugins))

all: plugin_info.h $(plugins)

clean: rm-plugin_info.h $(pluginsclean) package-clean

package: all
	rm -rf ${PACKAGE_DIR}
	mkdir -p ${PACKAGE_DIR}/cloudtrail
	mkdir -p ${PACKAGE_DIR}/json
	cp plugins/cloudtrail/{libcloudtrail.so,README.md} ${PACKAGE_DIR}/cloudtrail/
	cp plugins/json/{libjson.so,README.md} ${PACKAGE_DIR}/json/
	tar -zcvf ${PACKAGE_DIR}.tar.gz	${PACKAGE_DIR}
	rm -rf ${PACKAGE_DIR}

plugin_info.h:
	$(CURL) -Lso $@ https://raw.githubusercontent.com/falcosecurity/libs/${FALCOSECURITY_LIBS_REVISION}/userspace/libscap/plugin_info.h

rm-plugin_info.h:
	rm -f plugin_info.h

$(plugins):
	cd plugins/$@ && make

%clean:
	cd plugins/$* && make clean
