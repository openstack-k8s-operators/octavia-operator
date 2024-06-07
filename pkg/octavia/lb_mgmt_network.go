/*
Licensed under the Apache License, Version 2.0 (the "License");
@you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package octavia

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/external"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/provider"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
)

type NetworkProvisioningSummary struct {
	TenantNetworkID         string
	TenantSubnetID          string
	TenantRouterPortID      string
	ProviderNetworkID       string
	RouterID                string
	SecurityGroupID         string
	ManagementSubnetCIDR    string
	ManagementSubnetGateway string
}

//
// TODO(beagles) we need to decide what, if any of the results of these methods we want to expose in the controller's
// status.
//

func findPort(client *gophercloud.ServiceClient, networkID string, ipAddress string, log *logr.Logger) (*ports.Port, error) {
	listOpts := ports.ListOpts{
		NetworkID: networkID,
	}
	allPages, err := ports.List(client, listOpts).AllPages()
	if err != nil {
		log.Error(err, fmt.Sprintf("Unable to list ports for %s", networkID))
		return nil, err
	}

	allPorts, err := ports.ExtractPorts(allPages)
	if err != nil {
		log.Error(err, "Unable to extract port information from list")
		return nil, err
	}
	if len(allPorts) > 0 {
		for _, port := range allPorts {
			if len(port.FixedIPs) > 0 && port.FixedIPs[0].IPAddress == ipAddress {
				return &port, nil
			}
		}
	}
	return nil, nil
}

func ensurePort(client *gophercloud.ServiceClient, tenantNetwork *networks.Network, tenantSubnet *subnets.Subnet,
	securityGroups *[]string, networkParameters *NetworkParameters, log *logr.Logger) (*ports.Port, error) {
	ipAddress := networkParameters.TenantGateway.String()
	p, err := findPort(client, tenantNetwork.ID, ipAddress, log)
	if err != nil {
		return nil, err
	}
	if p != nil {
		//
		// TODO(beagles): reconcile port properties? Is there anything to do? Security groups possibly.
		//
		return p, nil
	}
	log.Info("Unable to locate port, creating new one")
	asu := true
	createOpts := ports.CreateOpts{
		Name:         LbMgmtRouterPortName,
		AdminStateUp: &asu,
		NetworkID:    tenantNetwork.ID,
		FixedIPs: []ports.IP{
			{
				SubnetID:  tenantSubnet.ID,
				IPAddress: ipAddress,
			},
		},
		SecurityGroups: securityGroups,
	}
	p, err = ports.Create(client, createOpts).Extract()
	if err != nil {
		log.Error(err, "Error creating port")
		return nil, err
	}
	return p, nil
}

func ensureSubnet(client *gophercloud.ServiceClient, ipVersion int, createOpts subnets.CreateOpts, log *logr.Logger) (*subnets.Subnet, error) {
	listOpts := subnets.ListOpts{
		Name:      createOpts.Name,
		NetworkID: createOpts.NetworkID,
		TenantID:  createOpts.TenantID,
		IPVersion: ipVersion,
	}
	allPages, err := subnets.List(client, listOpts).AllPages()
	if err != nil {
		return nil, err
	}
	allSubnets, err := subnets.ExtractSubnets(allPages)
	if err != nil {
		return nil, err
	}

	var lbMgmtSubnet *subnets.Subnet
	if len(allSubnets) == 0 {
		log.Info(fmt.Sprintf("Creating Octavia management subnet \"%s\"", createOpts.Name))
		lbMgmtSubnet, err = subnets.Create(client, createOpts).Extract()
		if err != nil {
			return nil, err
		}
	} else {
		lbMgmtSubnet = &allSubnets[0]
		delta := subnets.UpdateOpts{}
		updateNeeded := false
		if lbMgmtSubnet.Description != createOpts.Description {
			delta.Description = &createOpts.Description
			updateNeeded = true
		}
		if lbMgmtSubnet.AllocationPools[0].Start != createOpts.AllocationPools[0].Start ||
			lbMgmtSubnet.AllocationPools[0].End != createOpts.AllocationPools[0].End {
			delta.AllocationPools = []subnets.AllocationPool{
				{
					Start: createOpts.AllocationPools[0].Start,
					End:   createOpts.AllocationPools[0].End,
				},
			}
			updateNeeded = true
		}
		if lbMgmtSubnet.GatewayIP != *createOpts.GatewayIP {
			delta.GatewayIP = createOpts.GatewayIP
			updateNeeded = true
		}
		if updateNeeded {
			log.Info(fmt.Sprintf("Updating Octavia management subnet \"%s\"", createOpts.Name))
			lbMgmtSubnet, err = subnets.Update(client, lbMgmtSubnet.ID, delta).Extract()
			if err != nil {
				return nil, err
			}
		}
	}
	return lbMgmtSubnet, nil
}

func getNetwork(client *gophercloud.ServiceClient, networkName string, serviceTenantID string) (*networks.Network, error) {
	listOpts := networks.ListOpts{
		Name:     networkName,
		TenantID: serviceTenantID,
	}
	allPages, err := networks.List(client, listOpts).AllPages()
	if err != nil {
		return nil, err
	}
	allNetworks, err := networks.ExtractNetworks(allPages)
	if err != nil {
		return nil, err
	}
	if len(allNetworks) > 0 {
		return &allNetworks[0], nil
	}
	return nil, nil
}

func getNetworkExt(client *gophercloud.ServiceClient, networkName string, serviceTenantID string) (*networks.Network, error) {
	extTrue := true
	listOpts := external.ListOptsExt{
		ListOptsBuilder: networks.ListOpts{
			Name:     networkName,
			TenantID: serviceTenantID,
		},
		External: &extTrue,
	}
	allPages, err := networks.List(client, listOpts).AllPages()
	if err != nil {
		return nil, err
	}
	allNetworks, err := networks.ExtractNetworks(allPages)
	if err != nil {
		return nil, err
	}
	if len(allNetworks) > 0 {
		return &allNetworks[0], nil
	}
	return nil, nil
}

func ensureNetwork(client *gophercloud.ServiceClient, createOpts networks.CreateOpts, log *logr.Logger,
	serviceTenantID string) (*networks.Network, error) {
	foundNetwork, err := getNetwork(client, createOpts.Name, serviceTenantID)
	if err != nil {
		return nil, err
	}

	if foundNetwork == nil {
		log.Info(fmt.Sprintf("Creating Octavia network \"%s\"", createOpts.Name))
		foundNetwork, err = networks.Create(client, createOpts).Extract()
		if err != nil {
			return nil, err
		}
	} else {
		emptyOpts := networks.UpdateOpts{}
		delta := networks.UpdateOpts{}
		if foundNetwork.Description != createOpts.Description {
			delta.Description = &createOpts.Description
		}
		if foundNetwork.AdminStateUp != *createOpts.AdminStateUp {
			delta.AdminStateUp = createOpts.AdminStateUp
		}
		if delta != emptyOpts {
			log.Info(fmt.Sprintf("Updating Octavia management network \"%s\"", createOpts.Name))
			foundNetwork, err = networks.Update(client, foundNetwork.ID, delta).Extract()
			if err != nil {
				return nil, err
			}
		}
	}
	return foundNetwork, nil
}

func ensureNetworkExt(client *gophercloud.ServiceClient, createOpts networks.CreateOpts, log *logr.Logger, serviceTenantID string) (*networks.Network, error) {
	foundNetwork, err := getNetworkExt(client, createOpts.Name, serviceTenantID)
	if err != nil {
		return nil, err
	}

	extTrue := true
	if foundNetwork == nil {
		segment := []provider.Segment{
			{
				NetworkType:     "flat",
				PhysicalNetwork: LbProvPhysicalNet,
			},
		}

		providerOpts := provider.CreateOptsExt{
			CreateOptsBuilder: createOpts,
			Segments:          segment,
		}

		extCreateOpts := external.CreateOptsExt{
			CreateOptsBuilder: providerOpts,
			External:          &extTrue,
		}

		log.Info(fmt.Sprintf("Creating Octavia network \"%s\"", createOpts.Name))
		foundNetwork, err = networks.Create(client, extCreateOpts).Extract()
		if err != nil {
			return nil, err
		}
	} else {
		emptyOpts := networks.UpdateOpts{}
		delta := networks.UpdateOpts{}
		if foundNetwork.Description != createOpts.Description {
			delta.Description = &createOpts.Description
		}
		if foundNetwork.AdminStateUp != *createOpts.AdminStateUp {
			delta.AdminStateUp = createOpts.AdminStateUp
		}
		if delta != emptyOpts {
			log.Info(fmt.Sprintf("Updating Octavia management network \"%s\"", createOpts.Name))
			foundNetwork, err = networks.Update(client, foundNetwork.ID, delta).Extract()
			if err != nil {
				return nil, err
			}
		}
	}
	return foundNetwork, nil
}

func ensureProvSubnet(
	client *gophercloud.ServiceClient,
	providerNetwork *networks.Network,
	networkParameters *NetworkParameters,
	log *logr.Logger,
) (*subnets.Subnet, error) {
	gatewayIP := ""
	createOpts := subnets.CreateOpts{
		Name:        LbProvSubnetName,
		Description: LbProvSubnetDescription,
		NetworkID:   providerNetwork.ID,
		TenantID:    providerNetwork.TenantID,
		CIDR:        networkParameters.ProviderCIDR.String(),
		IPVersion:   gophercloud.IPVersion(4),
		AllocationPools: []subnets.AllocationPool{
			{
				Start: networkParameters.ProviderAllocationStart.String(),
				End:   networkParameters.ProviderAllocationEnd.String(),
			},
		},
		GatewayIP: &gatewayIP,
	}
	return ensureSubnet(client, 4, createOpts, log)
}

func ensureProvNetwork(client *gophercloud.ServiceClient, netDetails *octaviav1.OctaviaLbMgmtNetworks, serviceTenantID string, log *logr.Logger) (
	*networks.Network, error) {
	_, err := getNetwork(client, LbProvNetName, serviceTenantID)
	if err != nil {
		return nil, err
	}

	asu := true
	createOpts := networks.CreateOpts{
		Name:                  LbProvNetName,
		Description:           LbProvNetDescription,
		AdminStateUp:          &asu,
		TenantID:              serviceTenantID,
		AvailabilityZoneHints: netDetails.AvailabilityZones,
	}
	provNet, err := ensureNetworkExt(client, createOpts, log, serviceTenantID)
	if err != nil {
		return nil, err
	}

	return provNet, nil
}

func ensureLbMgmtSubnet(
	client *gophercloud.ServiceClient,
	tenantNetwork *networks.Network,
	networkParameters *NetworkParameters,
	log *logr.Logger,
) (*subnets.Subnet, error) {
	var ipVersion int
	if networkParameters.TenantCIDR.Addr().Is6() {
		ipVersion = 6
	} else {
		ipVersion = 4
	}

	var createOpts subnets.CreateOpts
	if ipVersion == 6 {
		gatewayIP := LbMgmtSubnetIPv6GatewayIP
		createOpts = subnets.CreateOpts{
			Name:            LbMgmtSubnetName,
			Description:     LbMgmtSubnetDescription,
			NetworkID:       tenantNetwork.ID,
			TenantID:        tenantNetwork.TenantID,
			CIDR:            networkParameters.TenantCIDR.String(),
			IPVersion:       gophercloud.IPVersion(ipVersion),
			IPv6AddressMode: LbMgmtSubnetIPv6AddressMode,
			IPv6RAMode:      LbMgmtSubnetIPv6RAMode,
			AllocationPools: []subnets.AllocationPool{
				{
					Start: networkParameters.TenantAllocationStart.String(),
					End:   networkParameters.TenantAllocationEnd.String(),
				},
			},
			GatewayIP: &gatewayIP,
			// TODO(beagles): ipv6 host routes
		}
	} else {
		gatewayIP := LbMgmtSubnetGatewayIP
		createOpts = subnets.CreateOpts{
			Name:        LbMgmtSubnetName,
			Description: LbMgmtSubnetDescription,
			NetworkID:   tenantNetwork.ID,
			TenantID:    tenantNetwork.TenantID,
			CIDR:        networkParameters.TenantCIDR.String(),
			IPVersion:   gophercloud.IPVersion(ipVersion),
			AllocationPools: []subnets.AllocationPool{
				{
					Start: networkParameters.TenantAllocationStart.String(),
					End:   networkParameters.TenantAllocationEnd.String(),
				},
			},
			HostRoutes: []subnets.HostRoute{
				{
					DestinationCIDR: networkParameters.ProviderCIDR.String(),
					NextHop:         networkParameters.TenantGateway.String(),
				},
			},
			GatewayIP: &gatewayIP,
		}
	}
	return ensureSubnet(client, ipVersion, createOpts, log)
}

func getLbMgmtNetwork(client *gophercloud.ServiceClient, serviceTenantID string) (*networks.Network, error) {
	return getNetwork(client, LbMgmtNetName, serviceTenantID)
}

func ensureLbMgmtNetwork(client *gophercloud.ServiceClient, networkDetails *octaviav1.OctaviaLbMgmtNetworks,
	serviceTenantID string, log *logr.Logger) (*networks.Network, error) {
	mgmtNetwork, err := getLbMgmtNetwork(client, serviceTenantID)
	if err != nil {
		return nil, err
	}

	if networkDetails == nil && mgmtNetwork == nil {
		return nil, fmt.Errorf("Cannot find network \"%s\"", LbMgmtNetName)
	}

	asu := true
	createOpts := networks.CreateOpts{
		Name:                  LbMgmtNetName,
		Description:           LbMgmtNetDescription,
		AdminStateUp:          &asu,
		TenantID:              serviceTenantID,
		AvailabilityZoneHints: networkDetails.AvailabilityZones,
	}
	mgmtNetwork, err = ensureNetwork(client, createOpts, log, serviceTenantID)
	if err != nil {
		return nil, err
	}

	return mgmtNetwork, nil
}

func externalFixedIPs(subnetID string, networkParameters *NetworkParameters) []routers.ExternalFixedIP {
	ips := []routers.ExternalFixedIP{
		{
			IPAddress: networkParameters.ProviderGateway.String(),
			SubnetID:  subnetID,
		},
	}
	return ips
}

func compareExternalFixedIPs(a []routers.ExternalFixedIP, b []routers.ExternalFixedIP) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].IPAddress != b[i].IPAddress {
			return false
		}
		if a[i].SubnetID != b[i].SubnetID {
			return false
		}
	}
	return true
}

// reconcileRouter compares existing router properties against what is expected/desired and updates the router if
// necessary!
func reconcileRouter(client *gophercloud.ServiceClient, router *routers.Router,
	gatewayNetwork *networks.Network,
	gatewaySubnet *subnets.Subnet,
	networkParameters *NetworkParameters,
	log *logr.Logger) (*routers.Router, error) {

	if !router.AdminStateUp {
		return router, fmt.Errorf("Router %s is not up", router.Name)
	}

	// TODO(beagles) check the status string.
	// if router.Status == ?

	needsUpdate := false
	updateInfo := routers.UpdateOpts{}
	enableSNAT := false
	fixedIPs := externalFixedIPs(gatewaySubnet.ID, networkParameters)

	//
	// TODO(beagles) we don't care about the other fields right now because we
	// are just going with neutron defaults but in the future we may care about
	// Distributed (oddly HA doesn't seem to be an option)
	//
	gatewayInfo := router.GatewayInfo
	if gatewayNetwork.ID != gatewayInfo.NetworkID || *gatewayInfo.EnableSNAT ||
		!compareExternalFixedIPs(gatewayInfo.ExternalFixedIPs, fixedIPs) {
		gwInfo := routers.GatewayInfo{
			NetworkID:        gatewayNetwork.ID,
			EnableSNAT:       &enableSNAT,
			ExternalFixedIPs: fixedIPs,
		}
		updateInfo.GatewayInfo = &gwInfo
		needsUpdate = true
	}
	if needsUpdate {
		updatedRouter, err := routers.Update(client, router.ID, updateInfo).Extract()
		if err != nil {
			return nil, err
		}
		log.Info(fmt.Sprintf("Updated octavia management router %s", router.ID))
		return updatedRouter, nil
	}

	return router, nil
}

// findRouter is a simple helper method...
func findRouter(client *gophercloud.ServiceClient, log *logr.Logger) (*routers.Router, error) {
	listOpts := routers.ListOpts{
		Name: LbRouterName,
	}
	allPages, err := routers.List(client, listOpts).AllPages()
	if err != nil {
		log.Error(err, "Unable to list routers")
		return nil, err
	}
	allRouters, err := routers.ExtractRouters(allPages)
	if err != nil {
		log.Error(err, "Unable to extract router results")
		return nil, err
	}
	if len(allRouters) > 0 {
		for _, router := range allRouters {
			if router.Name == LbRouterName {
				return &router, nil
			}
		}
	}
	return nil, nil
}

//
// IMPORTANT NOTE:
// Take care to specify the project/tenant IDs when querying AND creating resources.
// Otherwise, the project IDs on the security groups and rules may not match and
// errors will occur as the code attempts to create duplicate rules. Ask me how I
// know -- beagles
//

// findSecurityGroupRule is different than the other findX helper functions because of the wide variety of
// potential values
func findSecurityGroupRule(client *gophercloud.ServiceClient, criteria *rules.ListOpts, log *logr.Logger) (*rules.SecGroupRule, error) {
	//
	// Strip description out of search. While informative, we are not concerned with that field.
	//
	listOpts := *criteria
	listOpts.Description = ""

	allPages, err := rules.List(client, listOpts).AllPages()

	if err != nil {
		log.Error(err, "findSecurityGroupRule: Unable to find security group rule")
		return nil, err
	}
	allRules, err := rules.ExtractRules(allPages)
	if err != nil {
		log.Error(err, "findSecurityGroupRule: error extracting security group rule")
		return nil, err
	}
	if len(allRules) != 0 {
		return &allRules[0], nil
	}

	return nil, nil
}

func strToRuleEtherType(v string) rules.RuleEtherType {
	if v == "IPv6" {
		return rules.EtherType6
	}
	return rules.EtherType4
}

func strToRuleProtocol(p string) rules.RuleProtocol {
	switch p {
	case "tcp":
		return rules.ProtocolTCP
	case "udp":
		return rules.ProtocolUDP
	}
	return ""
}

func ensureSecurityGroupRules(client *gophercloud.ServiceClient, securityGroup *groups.SecGroup, rulesDefinitions []rules.ListOpts, log *logr.Logger) error {
	for _, r := range rulesDefinitions {
		r.TenantID = securityGroup.TenantID
		r.SecGroupID = securityGroup.ID
		r.Direction = "ingress"
		rule, err := findSecurityGroupRule(client, &r, log)
		// Don't break on error if not found, but create the rest.
		if err != nil {
			log.Error(err, fmt.Sprintf("ensureSecurityGroupRules: error searching for %s", r.Description))
			continue
		}
		if rule != nil {
			// There is a rule that matches this description, carry on.
			continue
		}
		//
		// Rule not found. Create a new one.
		createOpts := rules.CreateOpts{
			Description:  r.Description,
			EtherType:    strToRuleEtherType(r.EtherType),
			PortRangeMax: r.PortRangeMax,
			PortRangeMin: r.PortRangeMin,
			Protocol:     strToRuleProtocol(r.Protocol),
			SecGroupID:   securityGroup.ID,
			Direction:    rules.DirIngress,
			ProjectID:    securityGroup.TenantID,
		}
		_, err = rules.Create(client, createOpts).Extract()
		if err != nil {
			log.Error(err, fmt.Sprintf("ensureSecurityGroupRules: error creating rule %s", r.Description))
		}
	}
	return nil
}

type ensureRules func(client *gophercloud.ServiceClient, securityGroup *groups.SecGroup, log *logr.Logger) error

func ensureMgmtRules(client *gophercloud.ServiceClient, securityGroup *groups.SecGroup, log *logr.Logger) error {
	rulesDefinitions := []rules.ListOpts{
		{
			Description:  "ssh port IPv4 rule",
			PortRangeMax: 22,
			PortRangeMin: 22,
			EtherType:    "IPv4",
			Protocol:     "tcp",
		},
		{
			Description:  "ssh port IPv6 rule",
			PortRangeMax: 22,
			PortRangeMin: 22,
			EtherType:    "IPv6",
			Protocol:     "tcp",
		},
		{
			Description:  "amphora agent port IPv4 rule",
			PortRangeMax: 9443,
			PortRangeMin: 9443,
			EtherType:    "IPv4",
			Protocol:     "tcp",
		},
		{
			Description:  "amphora agent port IPv6 rule",
			PortRangeMax: 9443,
			PortRangeMin: 9443,
			EtherType:    "IPv6",
			Protocol:     "tcp",
		},
	}
	return ensureSecurityGroupRules(client, securityGroup, rulesDefinitions, log)
}

func ensureHealthMgrRules(client *gophercloud.ServiceClient, securityGroup *groups.SecGroup, log *logr.Logger) error {
	healthManagerRules := []rules.ListOpts{
		{
			Description:  "health manager status port IPv4 rule",
			PortRangeMax: 5555,
			PortRangeMin: 5555,
			EtherType:    "IPv4",
			Protocol:     "udp",
		},
		{
			Description:  "health manager status port IPv6 rule",
			PortRangeMax: 5555,
			PortRangeMin: 5555,
			EtherType:    "IPv6",
			Protocol:     "udp",
		},
		{
			Description:  "log offloading udp IPv4 rule",
			PortRangeMax: 514,
			PortRangeMin: 514,
			EtherType:    "IPv4",
			Protocol:     "udp",
		},
		{
			Description:  "log offloading udp IPv6 rule",
			PortRangeMax: 514,
			PortRangeMin: 514,
			EtherType:    "IPv6",
			Protocol:     "udp",
		},
		{
			Description:  "log offloading udp IPv4 rule",
			PortRangeMax: 514,
			PortRangeMin: 514,
			EtherType:    "IPv4",
			Protocol:     "tcp",
		},
		{
			Description:  "log offloading udp IPv6 rule",
			PortRangeMax: 514,
			PortRangeMin: 514,
			EtherType:    "IPv6",
			Protocol:     "tcp",
		},
	}
	return ensureSecurityGroupRules(client, securityGroup, healthManagerRules, log)
}

func findSecurityGroup(client *gophercloud.ServiceClient, tenantID string, groupName string, log *logr.Logger) (*groups.SecGroup, error) {
	listOpts := groups.ListOpts{
		TenantID: tenantID,
	}
	allPages, err := groups.List(client, listOpts).AllPages()
	if err != nil {
		log.Error(err, "findSecurityGroup: Unable to find security groups")
		return nil, err
	}
	allGroups, err := groups.ExtractGroups(allPages)
	if err != nil {
		log.Error(err, "findSecurityGroup: error extracting security groups")
		return nil, err
	}
	for _, group := range allGroups {
		if group.Name == groupName {
			return &group, nil
		}
	}
	return nil, nil
}

func ensureSecurityGroup(
	client *gophercloud.ServiceClient,
	tenantID string,
	groupName string,
	ruleFn ensureRules,
	log *logr.Logger) (
	string, error) {

	secGroup, err := findSecurityGroup(client, tenantID, groupName, log)
	if err != nil {
		return "", err
	}
	if secGroup == nil {
		log.Info(fmt.Sprintf("ensureSecurityGroup: security group %s not found, creating...", groupName))
		createOpts := groups.CreateOpts{
			Name:     groupName,
			TenantID: tenantID,
		}
		secGroup, err = groups.Create(client, createOpts).Extract()
		if err != nil {
			log.Error(err, fmt.Sprintf("ensureLbMgmtSecurityGroup: unable to create security group %s",
				groupName))
			return "", err
		}
	}

	err = ruleFn(client, secGroup, log)
	if err != nil {
		return "", err
	}
	return secGroup.ID, nil
}

// EnsureAmphoraManagementNetwork - retrieve, create and reconcile the Octavia management network for the in cluster link to the
// management tenant network.
func EnsureAmphoraManagementNetwork(
	ctx context.Context,
	ns string,
	tenantName string,
	netDetails *octaviav1.OctaviaLbMgmtNetworks,
	networkParameters *NetworkParameters,
	log *logr.Logger,
	helper *helper.Helper,
) (NetworkProvisioningSummary, error) {
	o, err := GetOpenstackClient(ctx, ns, helper)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}
	client, err := GetNetworkClient(o)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}
	serviceTenant, err := GetProject(o, tenantName)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}

	tenantNetwork, err := ensureLbMgmtNetwork(client, netDetails, serviceTenant.ID, log)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}
	tenantSubnet, err := ensureLbMgmtSubnet(client, tenantNetwork, networkParameters, log)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}

	lbMgmtSecurityGroupID, err := ensureSecurityGroup(client, tenantNetwork.TenantID, LbMgmtNetworkSecurityGroupName, ensureMgmtRules, log)
	if err != nil {
		log.Error(err, "Unable to complete configuration of management network security groups, continuing...")
	}
	lbHealthSecurityGroupID, err := ensureSecurityGroup(client, tenantNetwork.TenantID, LbMgmtHealthManagerSecurityGroupName, ensureHealthMgrRules, log)
	if err != nil {
		log.Error(err, "Unable to complete configuration of management network security groups, continuing...")
	}

	securityGroups := []string{lbMgmtSecurityGroupID, lbHealthSecurityGroupID}

	tenantRouterPort, err := ensurePort(client, tenantNetwork, tenantSubnet, &securityGroups, networkParameters, log)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}
	adminTenant, err := GetProject(o, AdminTenant)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}

	_, err = ensureSecurityGroup(client, adminTenant.ID, LbProvNetworkSecurityGroupName, ensureMgmtRules, log)
	if err != nil {
		log.Error(err, "Unable to complete configuration of octavia provider network security groups, continuing...")
	}
	_, err = ensureSecurityGroup(client, adminTenant.ID, LbProvHealthManagerSecurityGroupName, ensureHealthMgrRules, log)
	if err != nil {
		log.Error(err, "Unable to complete configuration of octavia provider network security groups, continuing...")
	}

	providerNetwork, err := ensureProvNetwork(client, netDetails, adminTenant.ID, log)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}

	providerSubnet, err := ensureProvSubnet(client, providerNetwork, networkParameters, log)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}

	router, err := findRouter(client, log)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}
	if router != nil {
		log.Info("Router object found, reconciling")
		router, err = reconcileRouter(client, router, providerNetwork, providerSubnet, networkParameters, log)
		if err != nil {
			return NetworkProvisioningSummary{}, err
		}
		log.Info(fmt.Sprintf("Reconciled router %s (%s)", router.Name, router.ID))
	} else {
		log.Info("Creating octavia provider router")
		enableSNAT := false
		gatewayInfo := routers.GatewayInfo{
			NetworkID:        providerNetwork.ID,
			EnableSNAT:       &enableSNAT,
			ExternalFixedIPs: externalFixedIPs(providerSubnet.ID, networkParameters),
		}
		adminStateUp := true
		createOpts := routers.CreateOpts{
			Name:                  LbRouterName,
			AdminStateUp:          &adminStateUp,
			GatewayInfo:           &gatewayInfo,
			AvailabilityZoneHints: netDetails.AvailabilityZones,
		}
		router, err = routers.Create(client, createOpts).Extract()
		if err != nil {
			log.Error(err, "Unable to create router object")
			return NetworkProvisioningSummary{}, err
		}
	}
	if tenantRouterPort.DeviceID == "" {
		interfaceOpts := routers.AddInterfaceOpts{
			PortID: tenantRouterPort.ID,
		}
		_, err := routers.AddInterface(client, router.ID, interfaceOpts).Extract()
		if err != nil {
			log.Error(err, fmt.Sprintf("Unable to add interface port %s to router %s", tenantRouterPort.ID, router.ID))
		}
	} else if tenantRouterPort.DeviceID != router.ID {
		return NetworkProvisioningSummary{},
			fmt.Errorf("Port %s has unexpected device ID %s and cannot be added to router %s", tenantRouterPort.ID,
				tenantRouterPort.DeviceID, router.ID)
	}

	return NetworkProvisioningSummary{
		TenantNetworkID:         tenantNetwork.ID,
		TenantSubnetID:          tenantSubnet.ID,
		TenantRouterPortID:      tenantRouterPort.ID,
		ProviderNetworkID:       providerNetwork.ID,
		RouterID:                router.ID,
		SecurityGroupID:         lbMgmtSecurityGroupID,
		ManagementSubnetCIDR:    networkParameters.TenantCIDR.String(),
		ManagementSubnetGateway: networkParameters.ProviderGateway.String(),
	}, nil
}
