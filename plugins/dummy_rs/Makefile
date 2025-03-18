# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2025 The Falco Authors.
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
CARGO ?= cargo

NAME := dummy_rs
OUTPUT := lib$(NAME).so

all: $(OUTPUT)

clean:
	@rm -f $(OUTPUT) && rm -rf target

PHONY: $(OUTPUT)
$(OUTPUT): 
	 $(CARGO) build --release && mv target/release/libdummy_rs.so .

PHONY: debug
debug: 
	 $(CARGO) build && mv target/debug/libdummy_rs.so .

readme:
	@$(READMETOOL) -p ./$(OUTPUT) -f README.md
