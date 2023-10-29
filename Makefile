#!/usr/bin/env make -f

PACKAGE_DIR ?= package
OBFUSCATE_DIR ?= obfuscate
OBFUSCATOR ?= cythonize

.PHONY: all clean clean-docker clean-vagrant clean-$(PACKAGE_DIR) clean-$(OBFUSCATE_DIR) docker vagrant stop-docker stop-vagrant $(OBFUSCATE_DIR)-%

all: $(OBFUSCATE_DIR)-package

clean: clean-docker clean-vagrant clean-$(PACKAGE_DIR) clean-$(OBFUSCATE_DIR)

clean-docker:
	@docker compose kill --remove-orphans
	@docker compose rm --force
	@docker volume prune --all --force

clean-vagrant:
	@vagrant destroy --force

clean-$(PACKAGE_DIR):
	@rm -rf $(PACKAGE_DIR)

clean-$(OBFUSCATE_DIR):
	@[ ! -d "$(OBFUSCATE_DIR)" ] || make -C "$(OBFUSCATE_DIR)" clean
	@rm -rf "$(OBFUSCATE_DIR)"

docker:
	@docker compose up --build -d

vagrant:
	@scripts/vagrant.sh

stop-docker:
	@docker compose down

stop-vagrant:
	@vagrant halt

$(PACKAGE_DIR):
	@scripts/package.sh "$(PACKAGE_DIR)"

$(OBFUSCATE_DIR):
	@scripts/template.sh . "$(OBFUSCATE_DIR)"
	@"scripts/obfuscate-$(OBFUSCATOR).sh" ca/server "$(OBFUSCATE_DIR)/ca/server"
	@"scripts/obfuscate-$(OBFUSCATOR).sh" web/server "$(OBFUSCATE_DIR)/web/server"

$(OBFUSCATE_DIR)-%: $(OBFUSCATE_DIR)
	@make -C "$(OBFUSCATE_DIR)" "$*"
