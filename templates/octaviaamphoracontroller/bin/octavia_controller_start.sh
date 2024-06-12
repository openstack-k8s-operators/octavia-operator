#!/bin/bash
#
# Copyright 2024 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
set -ex

/usr/local/bin/container-scripts/octavia_mgmt_subnet_route.py octavia "$MGMT_CIDR" "$MGMT_GATEWAY"

if [ "$1" = "octavia-health-manager" ]; then
    /usr/local/bin/container-scripts/setipalias.py octavia
    /usr/local/bin/container-scripts/octavia_hm_advertisement.py octavia
fi

# Ignore possible errors
/usr/local/bin/container-scripts/octavia_status.py || true

exec /usr/bin/$1 --config-file /usr/share/octavia/octavia-dist.conf --config-file /etc/octavia/octavia.conf
