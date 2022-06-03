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
CURL = curl

SIMDJSON_VER ?= 2.0.3
SIMDJSON_URL = https://github.com/simdjson/simdjson/releases/download/v${SIMDJSON_VER}/simdjson

PLUGIN_INFO_REPO     ?= falcosecurity/libs
PLUGIN_INFO_REVISION ?= 39ae7d40496793cf3d3e7890c9bbdc202263836b
PLUGIN_INFO_URL      =  https://raw.githubusercontent.com/${PLUGIN_INFO_REPO}/${PLUGIN_INFO_REVISION}/userspace/libscap/plugin_info.h

DEPS_DIR := deps

NAME := json
OUTPUT := lib$(NAME).so

all: $(OUTPUT)

clean:
	rm -rf *.so

deps_dir: ${DEPS_DIR}
	@mkdir -p ${DEPS_DIR}

plugin_info: deps_dir ${DEPS_DIR}/plugin_info.h
	@echo downloading plugin_info...
	@$(CURL) -Lso ${DEPS_DIR}/plugin_info.h $(PLUGIN_INFO_URL)

simdjson: deps_dir ${DEPS_DIR}/simdjson.h ${DEPS_DIR}/simdjson.cpp
	@echo downloading simdjson...
	@$(CURL) -Lso ${DEPS_DIR}/simdjson.h $(SIMDJSON_URL).h
	@$(CURL) -Lso ${DEPS_DIR}/simdjson.cpp $(SIMDJSON_URL).cpp

deps: plugin_info simdjson

.PHONY: $(OUTPUT)
$(OUTPUT): deps *.cpp
	g++ -std=c++0x -fPIC -shared -o $(OUTPUT) *.cpp ${DEPS_DIR}/*.cpp