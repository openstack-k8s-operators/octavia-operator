#!/usr/bin/env python3
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

from pyroute2 import IPRoute

ip = IPRoute()

ifaces = {}

for link in ip.get_links():
    attrs = {k: v for k, v in link['attrs']}
    ifaces[link['index']] = attrs['IFLA_IFNAME']

for addr in ip.get_addr():
    attrs = {k: v for k, v in addr['attrs']}
    print(f"addr {attrs['IFA_ADDRESS']}/{addr['prefixlen']} "
          f"dev {ifaces[addr['index']]}")

for route in ip.get_routes():
    attrs = {k: v for k, v in route['attrs']}
    if attrs['RTA_TABLE'] != 254:
        continue
    suffix = f"/{route['dst_len']}" if route['dst_len'] else ""
    route_str = f"route {attrs.get('RTA_DST', 'default')}{suffix} "
    if attrs.get('RTA_GATEWAY'):
        route_str += f"via {attrs.get('RTA_GATEWAY')} "
    route_str += f"dev {ifaces[attrs['RTA_OIF']]} "
    if attrs.get('RTA_PREFSRC'):
        suffix = f"/{route['src_len']}" if route['src_len'] else ""
        route_str += f"prefsrc {attrs.get('RTA_PREFSRC')}{suffix} "

    print(route_str)
