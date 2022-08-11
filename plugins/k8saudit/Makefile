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
GO ?= go
CURL ?= curl

FALCOSECURITY_FALCO_REPO ?= falcosecurity/falco
FALCOSECURITY_FALCO_REVISION ?= 65435d4418638176f68df9017df36cd5d94ba083

TEST_FILES_DIR := test_files
NAME := k8saudit
OUTPUT := lib$(NAME).so

ifeq ($(DEBUG), 1)
    GODEBUGFLAGS= GODEBUG=cgocheck=2
else
    GODEBUGFLAGS= GODEBUG=cgocheck=0
endif

all: $(OUTPUT)

clean:
	@rm -fr $(OUTPUT) test_files

test-files:
	@rm -fr ${TEST_FILES_DIR}
	@mkdir -p ${TEST_FILES_DIR}
	@cd ${TEST_FILES_DIR} \
		&& wget "https://github.com/${FALCOSECURITY_FALCO_REPO}/archive/${FALCOSECURITY_FALCO_REVISION}.tar.gz" -O falco.tar.gz \
		&& tar -xvf falco.tar.gz falco-${FALCOSECURITY_FALCO_REVISION}/test/trace_files/k8s_audit \
		&& mv falco-${FALCOSECURITY_FALCO_REVISION}/test/trace_files/k8s_audit/* ./ \
		&& rm -fr *.tar.gz *.txt falco-${FALCOSECURITY_FALCO_REVISION}

$(OUTPUT):
	@$(GODEBUGFLAGS) $(GO) build -buildmode=c-shared -o $(OUTPUT) ./plugin

readme:
	@$(READMETOOL) -p ./$(OUTPUT) -f README.md