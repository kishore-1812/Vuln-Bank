VULN_COMPOSE_FILE := ./vuln-bank/docker-compose.yml
SERVICE_NAME := web
CONTAINER_NAME := vuln-bank-web-1
IMAGE_NAME := vuln-bank-web

.PHONY: build up down restart logs

build:
#build the images
	docker compose -f $(VULN_COMPOSE_FILE) build --no-cache

up:
#run the containers
	docker compose -f $(VULN_COMPOSE_FILE) up -d

down:
# Stop the containers
	docker compose -f $(VULN_COMPOSE_FILE) down

restart: down up

remove:
	docker rm -f $(CONTAINER_NAME)
	docker rmi $(IMAGE_NAME)


logs:
#displays the logs
	docker compose -f $(VULN_COMPOSE_FILE) logs -f $(SERVICE_NAME)
	