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


NAME := k8smeta
OUTPUT := lib$(NAME).so

all: $(OUTPUT)

clean:
	rm -rf build $(OUTPUT)

# This Makefile requies CMake installed on the system
$(OUTPUT):
	mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Release ../ && make k8smeta -j6 && cp ./$(OUTPUT) ../$(OUTPUT)

readme:
	@$(READMETOOL) -p ./$(OUTPUT) -f README.md
