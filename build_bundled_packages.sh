#!/bin/sh
# Copyright (c) 2026 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the COPYING file.

set -e

bundled_actions=`cat bundled.txt`

./build_packages.sh $bundled_actions
