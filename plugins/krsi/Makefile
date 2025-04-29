NAME := krsi
OUTPUT := lib$(NAME).so

all: $(OUTPUT)

.PHONY: $(OUTPUT)
$(OUTPUT):
	 rustup component add rust-src --toolchain nightly-2025-03-15-$(shell uname -m)-unknown-linux-gnu
	 cargo build --release && mv target/release/$(OUTPUT) .

.PHONY: clean
clean:
	cargo clean
	@rm -f $(OUTPUT)

.PHONY: fmt
fmt:
	pre-commit run --all-files rust-fmt

.PHONY: test
test:
	cargo test --config 'target."cfg(all())".runner="sudo -E"' -- --include-ignored

.PHONY: readme
readme:
	@$(READMETOOL) -p ./$(OUTPUT) -f README.md
