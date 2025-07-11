# Copyright (c) 2025 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the COPYING file.

.PHONY: gen_dir bundled_packages packages dist lint dev_setup

lint:
	flake8
	./check_copyright.sh

gen_dir:
	mkdir -p gen

# Packages up all packages in the repo listed in the bundled.yaml file
bundled_packages: gen_dir
	./build_bundled_packages.sh

# Packages up all packages in the repo
packages: gen_dir
	./build_packages.sh

dist: packages
	cd gen && sha512sum * > CHECKSUMS.sha512

dev_setup:
	python3 -m pip install -r requirements-dev.txt
