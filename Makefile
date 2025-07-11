# Copyright (c) 2025 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the COPYING file.

.PHONY: bundled_packages packages dist lint

lint:
	flake8
	./check_copyright.sh

gen_dir:
	mkdir -p gen

# Packages up all packages in the repo listed in the bundled.yaml file
bundled_packages: gen_dir
	find . -mindepth 1 -maxdepth 1 -name '*-package' -type d -execdir grep -qF '{}' bundled.yaml ';' -execdir tar cf '{}'.tar '{}' ';'
	mv *.tar gen

# Packages up all packages in the repo
packages: gen_dir
	find . -mindepth 1 -maxdepth 1 -name "*-package" -type d -execdir tar cf {}.tar {} \;
	mv *.tar gen

dist: packages
	cd gen && sha512sum * > CHECKSUMS.sha512
