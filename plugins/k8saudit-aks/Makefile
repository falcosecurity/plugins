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

SHELL=/bin/bash -o pipefail
GO ?= go

NAME := k8saudit-aks
OUTPUT := lib$(NAME).so

ifeq ($(DEBUG), 1)
    GODEBUGFLAGS= GODEBUG=cgocheck=1
else
    GODEBUGFLAGS= GODEBUG=cgocheck=0
endif

all: $(OUTPUT)

clean:
	@rm -f *.so

$(OUTPUT): clean
	@$(GODEBUGFLAGS) $(GO) build -buildmode=c-shared -o $(OUTPUT) ./plugin

readme:
	@$(READMETOOL) -p ./$(OUTPUT) -f README.md

copy: all
	@cp ./$(OUTPUT) /usr/share/falco/plugins/
	@cp falco.yaml /etc/falco/falco.yaml

run-falco: copy
	@falco -c /etc/falco/falco.yaml
