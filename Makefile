# PenTools — Makefile
# Usage: make <target>

.DEFAULT_GOAL := help
COMPOSE := docker compose
WEB := $(COMPOSE) exec web
PYTHON := $(WEB) python manage.py

.PHONY: help up down build restart logs shell worker test migrate \
        superuser clean prune ps flower

# ─── Infrastructure ──────────────────────────────────────────────────────

up: ## Start all services (detached)
	@cp -n .env.example .env 2>/dev/null || true
	$(COMPOSE) up -d --remove-orphans

up-build: ## Build images and start all services
	@cp -n .env.example .env 2>/dev/null || true
	$(COMPOSE) up -d --build --remove-orphans

down: ## Stop all services
	$(COMPOSE) down

restart: ## Restart all services
	$(COMPOSE) restart

build: ## Build all images (no start)
	$(COMPOSE) build

ps: ## Show running containers
	$(COMPOSE) ps

logs: ## Follow logs for all containers
	$(COMPOSE) logs -f

logs-web: ## Follow Django web logs
	$(COMPOSE) logs -f web

logs-celery: ## Follow Celery worker logs
	$(COMPOSE) logs -f celery

flower: ## Open Flower in browser (Celery monitor)
	@echo "Flower: http://localhost:5555"
	@xdg-open http://localhost:5555 2>/dev/null || open http://localhost:5555 2>/dev/null || true

# ─── Development ─────────────────────────────────────────────────────────

shell: ## Open Django shell
	$(PYTHON) shell_plus 2>/dev/null || $(PYTHON) shell

bash: ## Open bash in web container
	$(WEB) bash

migrate: ## Run Django migrations
	$(PYTHON) migrate

makemigrations: ## Create new migrations
	$(PYTHON) makemigrations

superuser: ## Create Django superuser
	$(PYTHON) createsuperuser

collectstatic: ## Collect static files
	$(PYTHON) collectstatic --noinput

worker: ## Start Celery worker locally (dev mode, not in Docker)
	cd web && celery -A pentools worker --loglevel=debug --concurrency=4

# ─── Testing ─────────────────────────────────────────────────────────────

test: ## Run all tests
	$(WEB) pytest --tb=short -q

test-watch: ## Run tests in watch mode
	$(WEB) pytest-watch

coverage: ## Run tests with coverage report
	$(WEB) pytest --cov=. --cov-report=html --cov-report=term

# ─── Database ────────────────────────────────────────────────────────────

db-shell: ## Open PostgreSQL shell
	$(COMPOSE) exec db psql -U $${POSTGRES_USER:-pentools} -d $${POSTGRES_DB:-pentools}

db-dump: ## Dump database to backup file
	$(COMPOSE) exec db pg_dump -U $${POSTGRES_USER:-pentools} $${POSTGRES_DB:-pentools} > backup_$$(date +%Y%m%d_%H%M%S).sql
	@echo "Database dumped to backup_*.sql"

# ─── Cleanup ─────────────────────────────────────────────────────────────

clean: ## Remove stopped containers and dangling images
	$(COMPOSE) down --remove-orphans
	docker image prune -f

prune: ## WARNING: Remove ALL unused Docker resources
	@read -p "This removes all unused Docker resources. Continue? [y/N] " ans; \
	[ "$$ans" = "y" ] && docker system prune -af --volumes || true

# ─── Help ────────────────────────────────────────────────────────────────

help: ## Show this help message
	@echo ""
	@echo "  PenTools — Make Commands"
	@echo "  ─────────────────────────────────────────────────────"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
