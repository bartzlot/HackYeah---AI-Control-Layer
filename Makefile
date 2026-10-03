# AICL Makefile (lead). Targets: up down test deploy
SHELL := /bin/bash
GCP_VM ?= aicl-vm
GCP_ZONE ?= europe-central2-a

.PHONY: up down test deploy sync
sync:
	uv sync

up:
	docker compose up -d --build

down:
	docker compose down

test: sync
	uv run pytest -q --junitxml=reports/junit.xml

# deploy to the GCP VM (T-902): copy repo, build and start there
deploy:
	gcloud compute scp --recurse --zone $(GCP_ZONE) . $(GCP_VM):~/aicl
	gcloud compute ssh --zone $(GCP_ZONE) $(GCP_VM) --command "cd ~/aicl && docker compose up -d --build"
