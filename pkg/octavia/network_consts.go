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

package octavia

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

	// LbMgmtSubnetGatewayIP -
	LbMgmtSubnetGatewayIP = ""

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

	// LbProvSubnetPoolSize -
	LbProvSubnetPoolSize = 25

	// IPv4 consts

	// TODO(beagles): support IPv6 for the provider network.
	// LbRouterName -
	LbRouterName = "octavia-link-router"

	// LbProvPhysicalNet -
	LbProvPhysicalNet = "octavia"

	// LbMgmtRouterPortName
	LbMgmtRouterPortName = "lb-mgmt-router-port"

	// Network attachment details
	// LbNetworkAttachmentName
	LbNetworkAttachmentName = "octavia"

	//
	// Security group constants.
	//

	// LbMgmtNetworkSecurityGroup
	LbMgmtNetworkSecurityGroupName = "lb-mgmt-sec-grp"

	// LbMgmtHealthManagerSecurityGroup
	LbMgmtHealthManagerSecurityGroupName = "lb-health-mgr-sec-grp"

	// LbMgmtNetworkSecurityGroup
	LbProvNetworkSecurityGroupName = "lb-prov-sec-grp"

	// LbMgmtHealthManagerSecurityGroup
	LbProvHealthManagerSecurityGroupName = "lb-health-prov-sec-grp"
)
