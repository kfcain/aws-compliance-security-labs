.PHONY: lint test iac check all

all: lint test iac check

lint:
	ruff check .

test:
	pytest
	node --test 'scripts/*.test.mjs' shared/scf-mapper/src/mapper.test.js

iac:
	cfn-lint
	checkov --config-file .checkov.yaml

check:
	node scripts/validate-catalog.mjs
	node scripts/check-common-sync.mjs
