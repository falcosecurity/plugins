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

PLUGIN_INFO_H_DIR=./
CURL=curl
PLUGIN_SDK_CPP_GIT_REF=70d5feb28ebf57d5f546452c27e1608911e56a5f

NAME := dummy_c
OUTPUT := lib$(NAME).so

all: $(OUTPUT)

clean:
	rm -rf plugin-sdk-cpp.tar.gz sdk include $(OUTPUT)

plugin-sdk-cpp.tar.gz:
	$(CURL) -sLo plugin-sdk-cpp.tar.gz https://github.com/falcosecurity/plugin-sdk-cpp/archive/$(PLUGIN_SDK_CPP_GIT_REF).tar.gz

include: plugin-sdk-cpp.tar.gz
	tar -xaf plugin-sdk-cpp.tar.gz plugin-sdk-cpp-$(PLUGIN_SDK_CPP_GIT_REF)/include --strip-components=1


$(OUTPUT): include dummy.cpp
	g++ -std=c++0x -fPIC -Iinclude/ -shared -o $(OUTPUT) *.cpp

readme:
	@$(READMETOOL) -p ./$(OUTPUT) -f README.md
