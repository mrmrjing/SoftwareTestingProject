# VENV_NAME = env
# PYTHON = $(VENV_NAME)/bin/python
# PIP = $(VENV_NAME)/bin/pip
# REQ = requirements.txt
# SCRIPT = main.py

# .PHONY: run clean ls

# $(VENV_NAME): 
# 	python3 -m venv $(VENV_NAME)
# 	@echo "✅ Virtual environment created"

# $(VENV_NAME)/.installed: $(REQ) | $(VENV_NAME)
# 	$(PIP) install -r $(REQ)
# 	touch $(VENV_NAME)/.installed

# run: $(VENV_NAME)/.installed
# 	$(PYTHON) $(SCRIPT) $(ARG)

# clean:
# 	rm -rf $(VENV_NAME)

# ls: 
# 	ls -la $(VENV_NAME)

VENV_NAME = env
PYTHON = $(VENV_NAME)/bin/python
PIP = $(VENV_NAME)/bin/pip
REQ = requirements.txt
SCRIPT = main.py

.PHONY: run clean ls

$(VENV_NAME): 
	python3 -m venv $(VENV_NAME)
	@echo "✅ Virtual environment created"

$(VENV_NAME)/.installed: $(REQ) | $(VENV_NAME)
	$(PIP) install -r $(REQ)
	touch $(VENV_NAME)/.installed

# Extract additional arguments passed to make (excluding the target 'run').
ARGS := $(filter-out run,$(MAKECMDGOALS))

run: $(VENV_NAME)/.installed
	$(PYTHON) $(SCRIPT) $(ARGS)

clean:
	rm -rf $(VENV_NAME)

ls: 
	ls -la $(VENV_NAME)

# Dummy rule to prevent make from treating extra arguments as file targets.
%:
	@:
