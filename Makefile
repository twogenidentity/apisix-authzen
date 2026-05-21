COMPOSE     = docker compose -f tests/docker-compose.yml --env-file tests/.env
COMPOSE_IDP = docker compose -f tests/idp/docker-compose.yml --env-file tests/.env
VENV        = tests/.venv
PYTHON      = $(VENV)/bin/python
VENV_STAMP  = $(VENV)/.installed

.PHONY: test test-up test-down test-run test-venv test-logs test-ps \
        test-idp test-idp-up test-idp-down test-idp-run test-idp-logs

$(VENV_STAMP): tests/requirements.txt
	python3 -m venv $(VENV)
	$(PYTHON) -m pip install --quiet --upgrade pip
	$(PYTHON) -m pip install --quiet -r tests/requirements.txt
	touch $(VENV_STAMP)

test-venv: $(VENV_STAMP)

test-up:
	$(COMPOSE) up -d --build

test-down:
	$(COMPOSE) down -v

test-ps:
	$(COMPOSE) ps

test-logs:
	$(COMPOSE) logs -f

test-run: $(VENV_STAMP)
	mkdir -p reports
	cd tests && ../$(PYTHON) -m pytest -v --html=../reports/main.html --self-contained-html

test: test-up test-run test-down

# IDP integration tests (Keycloak + openid-connect + authzen)
test-idp-up:
	$(COMPOSE_IDP) up -d --build

test-idp-down:
	$(COMPOSE_IDP) down -v

test-idp-logs:
	$(COMPOSE_IDP) logs -f

test-idp-run: $(VENV_STAMP)
	mkdir -p reports
	cd tests/idp && ../../$(PYTHON) -m pytest -v --html=../../reports/idp.html --self-contained-html

test-idp: test-idp-up test-idp-run test-idp-down

test-all: test test-idp
