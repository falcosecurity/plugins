all: lib

# NOTE: using `-tags=containers_image_openpgp` to disable gpgme usage in containers/image.

.PHONY: lib
lib:
	CGO_ENABLED=1 go build -tags containers_image_openpgp -ldflags="-s -w" -v -o libworker.a -buildmode=c-archive .

.PHONY: exe
exe:
	CGO_ENABLED=1 go build -tags containers_image_openpgp -ldflags="-s -w" -tags exe -v -o worker  .

clean:
	rm -rf worker libworker.a libworker.h

.PHONY: test
test:
	go clean -testcache
	GOEXPERIMENT=loopvar go test -v -cover -race ./...