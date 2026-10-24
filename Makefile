.PHONY: setup serve fmt lint typecheck test eval audit check clean

PYTHON ?= python3
VENV   := .venv
PY     := $(VENV)/bin/python
BIN    := $(VENV)/bin

# Floors, not targets: a little under today's 96% precision and 83% recall, so
# a rule change that costs either fails `make check` without pinning the score.
MIN_PRECISION ?= 0.90
MIN_RECALL    ?= 0.80

# ------------------------------------------------------------------
# Setup and run
# ------------------------------------------------------------------

setup:
	@$(PYTHON) -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' || { \
		echo "ERROR: Python 3.11+ required, found $$($(PYTHON) -V)"; exit 1; }
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e ".[dev]"
	@echo ""
	@echo "Next: make serve   # UI at http://127.0.0.1:8741"

serve:
	$(BIN)/archibald serve

# ------------------------------------------------------------------
# Quality — `check` is every gate, in the order to run them
# ------------------------------------------------------------------

check: lint typecheck test eval

fmt:
	$(BIN)/ruff format .
	$(BIN)/ruff check --fix .

lint:
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .

typecheck:
	$(BIN)/mypy

test:
	$(BIN)/pytest -q

# Precision and recall against corpus/, failing below the floors above.
eval:
	$(BIN)/archibald eval --min-precision $(MIN_PRECISION) --min-recall $(MIN_RECALL)

# Advisories appear without anyone touching this repository, so this reports
# rather than gates.
audit:
	$(BIN)/pip-audit || true

clean:
	rm -rf $(VENV) .mypy_cache .pytest_cache .ruff_cache build dist *.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
