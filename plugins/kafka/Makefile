SHELL=/bin/bash -o pipefail
GO ?= go

NAME := kafka
OUTPUT := lib$(NAME).so

ifeq ($(DEBUG), 1)
    GODEBUGFLAGS= GODEBUG=cgocheck=1
else
    GODEBUGFLAGS= GODEBUG=cgocheck=0
endif

all: $(OUTPUT)

clean:
	@rm -f $(OUTPUT)

$(OUTPUT):
	@$(GODEBUGFLAGS) $(GO) build -buildmode=c-shared -o $(OUTPUT) ./plugin