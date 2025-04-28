NAME := krsi
OUTPUT := lib$(NAME).so

all: $(OUTPUT)

.PHONY: $(OUTPUT)
$(OUTPUT):
	 $(CARGO) build --release && mv target/release/$(NAME) .

.PHONY: clean
clean:
	cargo clean

.PHONY: fmt
fmt:
	pre-commit run --all-files rust-fmt

.PHONY: test
test:
	cargo test --config 'target."cfg(all())".runner="sudo -E"' -- --include-ignored

.PHONY: readme
readme:
	@$(READMETOOL) -p ./$(OUTPUT) -f README.md