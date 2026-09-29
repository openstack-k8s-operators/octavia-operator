#!/bin/bash
#
# Copyright 2022 Red Hat Inc.
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

set -e

function copy_config_dir {
    echo copying config dir $1
    for conf in $(find $1 -type f); do
        conf_base=$(basename $conf)

        # Ordered config files are consumed through oslo.config's config-dir.
        if [[ ${conf_base} =~ ^[0-9]{2}-config\.conf$ ]]; then
            cp -f ${conf} ${MERGEPATH}/octavia.conf.d/
            chmod 0660 ${MERGEPATH}/octavia.conf.d/${conf_base}
        else
            cp -f ${conf} ${MERGEPATH}/
        fi
    done
}
