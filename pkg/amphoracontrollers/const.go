/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package amphoracontrollers

// NOTE: Strictly speaking, these don't have to be package scope constants, but having them externally
// accessible might aide constructing functional tests later on.

const (
	// Common consts for Management network

	// LbMgmtNetName -
	LbMgmtNetName = "lb-mgmt-net"

	// LbMgmtNetDescription -
	LbMgmtNetDescription = "LBaaS Management Network"

	// LbMgmtSubnetName -
	LbMgmtSubnetName = "lb-mgmt-subnet"

	// LbMgmtSubnetDescription -
	LbMgmtSubnetDescription = "LBaaS Management Subnet"

	// IPv4 consts

	// LbMgmtSubnetCIDR -
	LbMgmtSubnetCIDR = "172.24.0.0/16"

	// LbMgmtSubnetAllocationPoolStart -
	LbMgmtSubnetAllocationPoolStart = "172.24.0.5"

	// LbMgmtSubnetAllocationPoolEnd -
	LbMgmtSubnetAllocationPoolEnd = "172.24.255.254"

	// LbMgmtSubnetGatewayIP -
	LbMgmtSubnetGatewayIP = ""

	// IPv6 consts
	// using Unique local address (fc00::/7)
	// with Global ID 6c:6261:6173 ("lbaas")

	// LbMgmtSubnetIPv6CIDR -
	LbMgmtSubnetIPv6CIDR = "fd6c:6261:6173:0001::/64"

	// LbMgmtSubnetIPv6AllocationPoolStart -
	LbMgmtSubnetIPv6AllocationPoolStart = "fd6c:6261:6173:0001::5"

	// LbMgmtSubnetIPv6AllocationPoolEnd -
	LbMgmtSubnetIPv6AllocationPoolEnd = "fd6c:6261:6173:0001:ffff:ffff:ffff:ffff"

	// LbMgmtSubnetIPv6AddressMode -
	LbMgmtSubnetIPv6AddressMode = "slaac"

	// LbMgmtSubnetIPv6RAMode -
	LbMgmtSubnetIPv6RAMode = "slaac"

	// LbMgmtSubnetIPv6GatewayIP -
	LbMgmtSubnetIPv6GatewayIP = ""

	// Common consts for Management provider network

	// LbProvNetName -
	LbProvNetName = "octavia-provider-net"

	// LbProvNetDescription -
	LbProvNetDescription = "LBaaS Management Provider Network"

	// LbProvSubnetName -
	LbProvSubnetName = "octavia-provider-subnet"

	// LbProvSubnetDescription -
	LbProvSubnetDescription = "LBaaS Management Provider Subnet"

	// IPv4 consts

	// LbProvSubnetCIDR -
	LbProvSubnetCIDR = "172.23.0.0/24"

	// LbProvSubnetAllocationPoolStart -
	LbProvSubnetAllocationPoolStart = "172.23.0.5"

	// LbProvSubnetAllocationPoolEnd -
	LbProvSubnetAllocationPoolEnd = "172.23.0.25"

	// LbProvSubnetGatewayIP -
	LbProvSubnetGatewayIP = "172.23.0.1"

	// TODO(beagles): support IPv6 for the provider network.
	// LbRouterName -
	LbRouterName = "octavia-link-router"

	// LbProvBridgeName -
	LbProvBridgeName = "br-octavia"

	// LbProvNetAttachName -
	LbProvNetAttachName = "octavia"

	// LbRouterFixedIPAddress
	LbRouterFixedIPAddress = "172.23.0.5"

	// LbMgmtRouterPortName
	LbMgmtRouterPortName = "lb-mgmt-router-port"

	// LbMgmtRouterPortIPIPv4
	LbMgmtRouterPortIPPv4 = "172.24.0.3"

	// LbMgmtRouterPortIPPv6
	LbMgmtRouterPortIPPv6 = "fd6c:6261:6173:0001::3"
)
