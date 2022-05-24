SHELL=/bin/bash -o pipefail
GO ?= go

NAME := github
OUTPUT := lib$(NAME).so

all: $(OUTPUT)

clean:
	@rm -f *.so *.h

$(OUTPUT): *.go
	@GODEBUG=cgocheck=2 $(GO) build -buildmode=c-shared -o $(OUTPUT)