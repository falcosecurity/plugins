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

.PHONY: all build clean release debug test

NAME := gcpaudit
OUTPUT := lib$(NAME)_rs.so

all: release

build: release

release:
	@echo "Building release version..."
	cargo build --release
	@cp target/release/lib$(NAME).so $(OUTPUT) || cp target/release/lib$(NAME).dylib $(OUTPUT) 2>/dev/null || true

debug:
	@echo "Building debug version..."
	cargo build
	@cp target/debug/lib$(NAME).so $(OUTPUT) || cp target/debug/lib$(NAME).dylib $(OUTPUT) 2>/dev/null || true

debug-universal:
	@echo "Building debug version..."
	cargo build
	@cp target/debug/lib$(NAME).so $(OUTPUT) || cp target/debug/lib$(NAME).dylib $(OUTPUT) 2>/dev/null || true

clean:
	cargo clean
	rm -f $(OUTPUT)

test:
	cargo test

check:
	cargo clippy -- -D warnings
	cargo fmt -- --check

fmt:
	cargo fmt

readme:
	@echo "Generate README with falco plugin tool if available"
