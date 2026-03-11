# arch-rand-gen development Makefile
# Assumes Arch localnet is already running on localhost:9002 / ws://localhost:10080
# Requires: cargo, cargo-build-sbf

SBF_TARGET := target/sbpf-solana-solana/release

.PHONY: all build server e2e keygen help

## ── Build ────────────────────────────────────────────────────────────────────

build: ## Compile server crate + SBF oracle on-chain program
	cargo build -p server
	cd oracle-program && cargo build-sbf

## ── Services ─────────────────────────────────────────────────────────────────

server: ## Start the oracle server (reads ~/.arch/ keys)
	cargo run -p server

## ── Key generation ───────────────────────────────────────────────────────────

keygen: ## Generate ~/.arch/.oracle_ed.key and print the Ed25519 pubkey to embed in shared/src/keys.rs
	cargo test -p server -- generate_oracle_ed_key --include-ignored --nocapture

## ── Tests ────────────────────────────────────────────────────────────────────

e2e: ## Deploy oracle program and run the end-to-end VRF fulfillment test
	cargo test -p e2e-tests -- test_deploy_and_request_randomness --include-ignored --nocapture

## ── Help ─────────────────────────────────────────────────────────────────────

help: ## Print this help
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make \033[36m<target>\033[0m\n\nTargets:\n"} \
	     /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
