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

try:
    interface_name = sys.argv[1]
    dst = sys.argv[2]
    gateway = sys.argv[3]
except IndexError:
    print(f"usage: {sys.argv[0]} <interface_name> <dst> <gateway>")
    sys.exit(1)

ip = IPRoute()

try:
    idx = ip.link_lookup(ifname=interface_name)[0]
except IndexError:
    print(f"Cannot find interface '{interface_name}', skipping")
    sys.exit(0)

try:
    ip.route('add', index=idx, dst=dst, gateway=gateway)
except Exception as e:
    print(f"Cannot set route {dst} via {gateway}: {e}")
