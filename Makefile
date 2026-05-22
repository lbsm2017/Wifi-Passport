# Wifi-Passport - shortcuts for the common workflows.
#
# Run `make` (or `make help`) to see all available targets.
# Override defaults from the command line, e.g.:
#     make export VAULT=home.passport
#     make test PYTHON=py -3.12

PYTHON ?= python
VAULT  ?= wifi.passport

.PHONY: help install test export verify inspect import benchmark clean


help:
	@echo "Wifi-Passport - available targets:"
	@echo ""
	@echo "  make install     Install runtime dependencies (argon2-cffi, cryptography)"
	@echo "  make test        Run the full pytest suite"
	@echo "  make export      Back up WiFi profiles to backup/$(VAULT)"
	@echo "  make verify      Decrypt and revalidate backup/$(VAULT)"
	@echo "  make inspect     Decrypt and list contents of backup/$(VAULT)"
	@echo "  make import      Restore profiles from backup/$(VAULT) (needs Admin)"
	@echo "  make benchmark   Time Argon2id parameter sets on this machine"
	@echo "  make clean       Remove pytest cache and __pycache__ directories"
	@echo ""
	@echo "Variables (override with VAR=value):"
	@echo "  PYTHON = $(PYTHON)"
	@echo "  VAULT  = $(VAULT)"


install:
	$(PYTHON) -m pip install -r requirements.txt


test:
	$(PYTHON) -m pytest test_wifi_passport.py -v


export:
	$(PYTHON) wifi_passport.py export $(VAULT)


verify:
	$(PYTHON) wifi_passport.py verify $(VAULT)


inspect:
	$(PYTHON) wifi_passport.py inspect $(VAULT)


import:
	$(PYTHON) wifi_passport.py import $(VAULT)


benchmark:
	$(PYTHON) wifi_passport.py benchmark


clean:
	-$(PYTHON) -c "import shutil, pathlib; [shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path('.').rglob('__pycache__')]"
	-$(PYTHON) -c "import shutil; shutil.rmtree('.pytest_cache', ignore_errors=True)"
