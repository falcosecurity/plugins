SHELL=/bin/bash -o pipefail
GO ?= go

NAME := k8saudit-ovh
OUTPUT := lib$(NAME).so

ifeq ($(DEBUG), 1)
    GODEBUGFLAGS= GODEBUG=cgocheck=1
else
    GODEBUGFLAGS= GODEBUG=cgocheck=0
endif

all: build

clean:
	@rm -f lib$(NAME).so

build: clean
	@$(GODEBUGFLAGS) $(GO) build -buildmode=c-shared -buildvcs=false -o $(OUTPUT) ./plugin

install:
	sudo cp $(OUTPUT) /usr/share/falco/plugins/