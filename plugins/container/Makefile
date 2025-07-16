# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2024 The Falco Authors.
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

NAME := container
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
PROJECT_ROOT_DIR = $(shell git rev-parse --show-toplevel)

ifeq ($(OS),Windows_NT)
    detected_OS := Windows
else
    detected_OS := $(shell sh -c 'uname 2>/dev/null || echo Unknown')
endif

ifeq ($(detected_OS),Windows)
    OUTPUT := $(NAME).dll
    OUTPUT_FILE := build/Release/$(OUTPUT)
else ifeq ($(detected_OS),Darwin)
    OUTPUT := lib$(NAME).dylib
    OUTPUT_FILE := build/$(OUTPUT)
else
    OUTPUT := lib$(NAME).so
    OUTPUT_FILE := build/$(OUTPUT)
endif

all: $(OUTPUT)

.PHONY: clean
clean:
	rm -rf build $(OUTPUT)
	make -C go-worker/ clean

# This Makefile requires CMake installed on the system
.PHONY: $(OUTPUT)
$(OUTPUT):
	cmake -B build -S . -DCMAKE_EXPORT_COMPILE_COMMANDS=ON && cmake --build build --target $(NAME) --parallel 6 --config Release && cp $(OUTPUT_FILE) $(OUTPUT)

.PHONY: test
test: $(OUTPUT)
	make -C build/ test && build/test/test && make -C go-worker/ test

readme:
	@$(READMETOOL) -p ./$(OUTPUT) -f README.md

# Requires clang-format-18
fmt:
	git ls-files --directory $(ROOT_DIR) | grep -E '\.(cpp|h|c)$$' | xargs clang-format-18 -Werror --style=file:${PROJECT_ROOT_DIR}/.clang-format -i --verbose