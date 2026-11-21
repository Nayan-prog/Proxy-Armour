# Thin wrapper around scripts/stack.py (Windows: scripts\armour.ps1 <command>).
#   make up | down | logs | ps | test | seed | demo
#   make seed ARGS="--password my-long-password --reset-policies"
#   make logs ARGS="proxy scanner"     make down ARGS=--volumes
PYTHON ?= python3
ARGS ?=

.PHONY: up down logs ps test seed demo
up down logs ps test seed demo:
	$(PYTHON) scripts/stack.py $@ $(ARGS)
