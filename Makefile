.PHONY: lint test iac policy check all

all: lint test iac check

lint:
	ruff check .

test:
	pytest
	node --test 'scripts/*.test.mjs' shared/scf-mapper/src/mapper.test.js

iac:
	cfn-lint
	checkov --config-file .checkov.yaml

policy:
	bash scripts/policy-gate.sh

check: policy
	node scripts/validate-catalog.mjs
	node scripts/check-common-sync.mjs
