#!/bin/sh
# Copyright (c) 2026 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the COPYING file.

set -e

artifacts_dir=gen
mkdir -p "$artifacts_dir"

if [ $# -gt 0 ]; then
	targets="$@"
else
	targets=$(ls ./src)
fi

for pkg in $targets; do
	version=$(awk '$1 == "version:" { print $2; exit }' "src/$pkg/config.yaml")
	tar --exclude='*/__pycache__' --exclude='*.pyc' --exclude='*.pyo' \
		-C src -cf "$artifacts_dir/${pkg}_${version}.tar" "$pkg"
done
