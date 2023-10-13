.DEFAULT_GOAL := help


.PHONY: fmt
fmt: ## format all TypeScript file
	npm run format

.PHONY: keys
keys: ## create EC(NIST P-256,prime256v1) key-pair
	openssl ecparam -name prime256v1 -genkey -out prime256v1_private_key.pem
	openssl ec -in prime256v1_private_key.pem -pubout -out prime256v1_public_key.pem
	npx eckles prime256v1_public_key.pem > remote_public_key.jwk

.PHONY: help
help: ## show this help
	@echo 'Usage: make [Targets]'
	@echo ''
	@echo 'Targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
