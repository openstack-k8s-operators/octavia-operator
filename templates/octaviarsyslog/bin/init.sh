#!/bin//bash
#
# Copyright 2020 Red Hat Inc.
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

# expect that the common.sh is in the same dir as the calling script
SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
. ${SCRIPTPATH}/common.sh --source-only

# Merge all templates from config CM
for dir in /var/lib/config-data/default; do
    merge_config_dir ${dir}
done

# Network configuration
if [ "$MGMT_CIDR" != "" ]; then
    /usr/local/bin/container-scripts/octavia_mgmt_subnet_route.py octavia "$MGMT_CIDR" "$MGMT_GATEWAY"
fi

idx=0
while true; do
    var_name="MGMT_CIDR${idx}"
    cidr="${!var_name}"
    if [ "$cidr" = "" ]; then
        break
    fi
    /usr/local/bin/container-scripts/octavia_mgmt_subnet_route.py octavia "$cidr" "$MGMT_GATEWAY"
    idx=$((idx+1))
done

/usr/local/bin/container-scripts/setipalias.py octavia rsyslog
/usr/local/bin/container-scripts/octavia_hm_advertisement.py octavia

/usr/local/bin/container-scripts/octavia_rsyslog_config.py octavia

# Ignore possible errors
/usr/local/bin/container-scripts/octavia_status.py || true
