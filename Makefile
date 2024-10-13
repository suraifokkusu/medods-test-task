.PHONY: build up test down logs clean rebuild

ifeq ($(OS),Windows_NT)
    BIN=.\bin\authservice.exe
    RM=if exist "$(BIN)" del /Q "$(BIN)"
    RMDIR=if exist bin rmdir /S /Q bin
    MKDIR=mkdir bin
else
    BIN=./bin/authservice
    RM=rm -f "$(BIN)"
    RMDIR=rm -rf bin
    MKDIR=mkdir -p bin
endif

build:
	docker-compose build

up:
	docker-compose up -d

migrate:
	docker-compose run --rm migrate

test:
	docker-compose run --rm test

down:
	docker-compose down

logs:
	docker-compose logs -f app

clean:
	@echo "Cleaning up build artifacts..."
	$(RM)
	$(RMDIR)
	docker-compose down --rmi all --volumes --remove-orphans
	go clean -cache -modcache
	@echo "Clean complete."

rebuild: clean build up
	@echo Rebuild complete.

local-build:
	@echo "Building application locally..."
	mkdir bin
	go build -o $(BIN) ./cmd/authservice
	@echo "Build complete: $(BIN)"
	
format:
	go fmt ./...