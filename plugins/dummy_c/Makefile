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

PLUGIN_INFO_H_DIR=./
FALCOSECURITY_PLUGIN_H_DIR=./sdk/
CURL=curl
PLUGIN_SDK_CPP_GIT_REF=52296e3a46d328791f61459e7be85ef00e44e786

NAME := dummy_c
OUTPUT := lib$(NAME).so

all: $(OUTPUT)

clean:
	rm -rf nlohmann sdk $(OUTPUT)

nlohmann/json.hpp:
	mkdir -p nlohmann && $(CURL) -sLo nlohmann/json.hpp https://github.com/nlohmann/json/releases/download/v3.10.2/json.hpp

sdk: sdk_dir sdk/plugin_info.h sdk/falcosecurity_plugin.h

sdk_dir:
	rm -rf sdk/ && mkdir sdk/

sdk/plugin_info.h:
	$(CURL) -sLo sdk/plugin_info.h  https://raw.githubusercontent.com/falcosecurity/plugin-sdk-cpp/$(PLUGIN_SDK_CPP_GIT_REF)/include/plugin_info.h

sdk/falcosecurity_plugin.h:
	$(CURL) -sLo sdk/falcosecurity_plugin.h https://raw.githubusercontent.com/falcosecurity/plugin-sdk-cpp/$(PLUGIN_SDK_CPP_GIT_REF)/include/falcosecurity_plugin.h

$(OUTPUT): sdk nlohmann/json.hpp dummy.cpp
	g++ -std=c++0x -fPIC -I$(FALCOSECURITY_PLUGIN_H_DIR) -I$(PLUGIN_INFO_H_DIR) -shared -o $(OUTPUT) dummy.cpp

readme:
	@$(READMETOOL) -p ./$(OUTPUT) -f README.md