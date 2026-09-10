.PHONY: check integration-check config-check

check:
	./scripts/verify.sh check

integration-check:
	./scripts/verify.sh runtime
	./scripts/verify.sh plane

config-check:
	go run ./cmd/identity-bridge -config examples/token-validation.config.json
