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

import sys
import socket

from pyroute2 import IPRoute

import ip_advertisement as ip_adv

try:
    interface_name = sys.argv[1]
except IndexError:
    print(f"usage: {sys.argv[0]} <interface_name>")
    sys.exit(1)

ip = IPRoute()

try:
    idx = ip.link_lookup(ifname=interface_name)[0]
except IndexError:
    print(f"Cannot find interface '{interface_name}', skipping")
    sys.exit(0)

addrs = ip.get_addr(index=idx)
ip_addrs = [
    dict(addr['attrs'])['IFA_ADDRESS']
    for addr in addrs]

for ip_addr in ip_addrs:
    try:
        ip_adv.send_ip_advertisement(interface_name, ip_addr)
    except Exception as e:
        print(f"Cannot send IP advertisement: {e}")
