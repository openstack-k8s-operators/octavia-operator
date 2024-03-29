#!/usr/bin/python3
import sys
import os
from pyroute2 import IPRoute

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

nodefile = "hm_%s" % node_name_env
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
ipaddress = ipfile.read()
ipfile.close()
if ipaddress:
    current_addresses = ip.get_addr(label=interface_name)
    # TODO(beagles): check IPv6, IIUC the  library will do some translation of
    # mask but it might not be what we want.
    if ipaddress not in current_addresses:
        ip.addr('add', index = octavia_interface[0], address=ipaddress, mask=32)
ip.close()
