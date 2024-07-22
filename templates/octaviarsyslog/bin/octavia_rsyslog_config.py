#!/usr/bin/python3

import sys
import os
import ipaddress
import netifaces
from pyroute2 import IPRoute

node_type = "rsyslog"

rsyslog_config = """
module(load="imudp")
input(type="imudp" address="{address}" port="514")
module(load="imtcp")
input(type="imtcp" address="{address}" port="514")
"""

try:
    interface_name = sys.argv[1]
except IndexError:
    print(f"usage: {sys.argv[0]} <interface_name>")
    sys.exit(1)

# The file containing our IP alias has the worker node name for
# a filename.
node_name_env = os.environ.get('NODE_NAME').strip()
if not node_name_env:
    print("NODE_NAME not set")
    sys.exit(1)

nodefile = f"{node_type}_{node_name_env}"
filename = os.path.join('/var/lib/hmports', nodefile)
if not os.path.exists(filename):
    print(f"Required alias address file {filename} does not exist")
    sys.exit(1)

ip = IPRoute()
octavia_interface = ip.link_lookup(ifname=interface_name)

if not len(octavia_interface):
    print('octavia network attachment not present')
    sys.exit(1)

ipfile = open(filename, "r")
ipaddr = ipfile.read()
ipfile.close()
if ipaddr:
    dest_file = "/var/lib/config-data/merged/09-octavia-listener.conf"
    with open(dest_file, "w") as fp:
        fp.write(rsyslog_config.format(address=ipaddr))
ip.close()
