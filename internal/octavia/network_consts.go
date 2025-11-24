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

	// LbMgmtNetNameAZ -
	LbMgmtNetNameAZ = "lb-mgmt-%s-net"

	// LbMgmtNetDescription -
	LbMgmtNetDescription = "LBaaS Management Network"

	// LbMgmtNetDescriptionAZ -
	LbMgmtNetDescriptionAZ = "LBaaS Management Network for %s"

	// LbMgmtSubnetName -
	LbMgmtSubnetName = "lb-mgmt-subnet"

	// LbMgmtSubnetNameAZ -
	LbMgmtSubnetNameAZ = "lb-mgmt-%s-subnet"

	// LbMgmtSubnetDescription -
	LbMgmtSubnetDescription = "LBaaS Management Subnet"

	// LbMgmtSubnetDescriptionAZ -
	LbMgmtSubnetDescriptionAZ = "LBaaS Management Subnet for %s"

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

	// LbProvPredictablePoolSize  -
	LbProvPredictablePoolSize = 25

	// IPv4 consts

	// LbRouterName is the name of the octavia link router
	// TODO(beagles): support IPv6 for the provider network.
	LbRouterName = "octavia-link-router"

	// LbProvPhysicalNet -
	LbProvPhysicalNet = "octavia"

	// LbMgmtRouterPortName is the name of the load balancer management router port
	LbMgmtRouterPortName = "lb-mgmt-router-port"

	// LbMgmtRouterPortNameAZ is the availability zone specific router port name template
	LbMgmtRouterPortNameAZ = "lb-mgmt-%s-router-port"

	// LbNetworkAttachmentName is the name for octavia network attachment details
	LbNetworkAttachmentName = "octavia"

	//
	// Security group constants.
	//

	// LbMgmtNetworkSecurityGroupName is the name of the load balancer management network security group
	LbMgmtNetworkSecurityGroupName = "lb-mgmt-sec-grp"

	// LbMgmtHealthManagerSecurityGroupName is the name of the load balancer management health manager security group
	LbMgmtHealthManagerSecurityGroupName = "lb-health-mgr-sec-grp"

	// LbProvNetworkSecurityGroupName is the name of the load balancer provider network security group
	LbProvNetworkSecurityGroupName = "lb-prov-sec-grp"

	// LbProvHealthManagerSecurityGroupName is the name of the load balancer provider health manager security group
	LbProvHealthManagerSecurityGroupName = "lb-health-prov-sec-grp"
)
