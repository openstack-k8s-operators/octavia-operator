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
	"net/netip"

	"github.com/go-logr/logr"
	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/external"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/provider"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/rbacpolicies"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/subnets"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
)

// NetworkProvisioningSummary -
// Type for conveying the results of the EnsureAmphoraManagementNetwork call.
type NetworkProvisioningSummary struct {
	TenantNetworkID            string
	SecurityGroupID            string
	ManagementSubnetCIDR       string
	ManagementSubnetGateway    string
	ManagementSubnetExtraCIDRs []string
}

//
// TODO(beagles) we need to decide what, if any of the results of these methods we want to expose in the controller's
// status.
//

func findPort(ctx context.Context, client *gophercloud.ServiceClient, networkID string, name string, log *logr.Logger) (*ports.Port, error) {
	listOpts := ports.ListOpts{
		NetworkID: networkID,
	}
	allPages, err := ports.List(client, listOpts).AllPages(ctx)
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
			if port.Name == name {
				return &port, nil
			}
		}
	}
	return nil, nil
}

func ensurePort(ctx context.Context, client *gophercloud.ServiceClient, availabilityZone *string, tenantNetwork *networks.Network, securityGroups *[]string, log *logr.Logger) (*ports.Port, bool, error) {
	var portName string
	if availabilityZone == nil {
		portName = LbMgmtRouterPortName
	} else {
		portName = fmt.Sprintf(LbMgmtRouterPortNameAZ, *availabilityZone)
	}

	p, err := findPort(ctx, client, tenantNetwork.ID, portName, log)
	if err != nil {
		return nil, false, err
	}
	if p != nil {
		//
		// TODO(beagles): reconcile port properties? Is there anything to do? Security groups possibly.
		//
		return p, false, nil
	}
	log.Info("Unable to locate port, creating new one")
	asu := true
	createOpts := ports.CreateOpts{
		Name:           portName,
		AdminStateUp:   &asu,
		NetworkID:      tenantNetwork.ID,
		SecurityGroups: securityGroups,
	}
	p, err = ports.Create(ctx, client, createOpts).Extract()
	if err != nil {
		log.Error(err, "Error creating port")
		return nil, false, err
	}
	return p, true, nil
}

func ensureSubnet(ctx context.Context, client *gophercloud.ServiceClient, ipVersion int, createOpts subnets.CreateOpts, log *logr.Logger) (*subnets.Subnet, error) {
	listOpts := subnets.ListOpts{
		Name:      createOpts.Name,
		NetworkID: createOpts.NetworkID,
		TenantID:  createOpts.TenantID,
		IPVersion: ipVersion,
	}
	allPages, err := subnets.List(client, listOpts).AllPages(ctx)
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
		lbMgmtSubnet, err = subnets.Create(ctx, client, createOpts).Extract()
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
			lbMgmtSubnet, err = subnets.Update(ctx, client, lbMgmtSubnet.ID, delta).Extract()
			if err != nil {
				return nil, err
			}
		}
	}
	return lbMgmtSubnet, nil
}

func getNetwork(ctx context.Context, client *gophercloud.ServiceClient, networkName string, serviceTenantID string) (*networks.Network, error) {
	listOpts := networks.ListOpts{
		Name:     networkName,
		TenantID: serviceTenantID,
	}
	allPages, err := networks.List(client, listOpts).AllPages(ctx)
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

func getNetworkExt(ctx context.Context, client *gophercloud.ServiceClient, networkName string, serviceTenantID string) (*networks.Network, error) {
	extTrue := true
	listOpts := external.ListOptsExt{
		ListOptsBuilder: networks.ListOpts{
			Name:     networkName,
			TenantID: serviceTenantID,
		},
		External: &extTrue,
	}
	allPages, err := networks.List(client, listOpts).AllPages(ctx)
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

func getSubnet(ctx context.Context, client *gophercloud.ServiceClient, subnetName string, serviceTenantID string) (*subnets.Subnet, error) {
	listOpts := subnets.ListOpts{
		Name:     subnetName,
		TenantID: serviceTenantID,
	}
	allPages, err := subnets.List(client, listOpts).AllPages(ctx)
	if err != nil {
		return nil, err
	}
	allSubnets, err := subnets.ExtractSubnets(allPages)
	if err != nil {
		return nil, err
	}
	if len(allSubnets) > 0 {
		return &allSubnets[0], nil
	}
	return nil, nil
}

func ensureNetwork(ctx context.Context, client *gophercloud.ServiceClient, createOpts networks.CreateOpts, log *logr.Logger,
	serviceTenantID string) (*networks.Network, error) {
	foundNetwork, err := getNetwork(ctx, client, createOpts.Name, serviceTenantID)
	if err != nil {
		return nil, err
	}

	if foundNetwork == nil {
		log.Info(fmt.Sprintf("Creating Octavia network \"%s\"", createOpts.Name))
		foundNetwork, err = networks.Create(ctx, client, createOpts).Extract()
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
			foundNetwork, err = networks.Update(ctx, client, foundNetwork.ID, delta).Extract()
			if err != nil {
				return nil, err
			}
		}
	}
	return foundNetwork, nil
}

func ensureNetworkExt(ctx context.Context, client *gophercloud.ServiceClient, createOpts networks.CreateOpts, log *logr.Logger, serviceTenantID string) (*networks.Network, error) {
	foundNetwork, err := getNetworkExt(ctx, client, createOpts.Name, serviceTenantID)
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
		foundNetwork, err = networks.Create(ctx, client, extCreateOpts).Extract()
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
			foundNetwork, err = networks.Update(ctx, client, foundNetwork.ID, delta).Extract()
			if err != nil {
				return nil, err
			}
		}
	}
	return foundNetwork, nil
}

func ensureProvSubnet(
	ctx context.Context,
	client *gophercloud.ServiceClient,
	providerNetwork *networks.Network,
	networkParameters *NetworkParameters,
	log *logr.Logger,
) (*subnets.Subnet, error) {
	gatewayIP := ""
	var ipVersion int
	if networkParameters.ProviderCIDR.Addr().Is6() {
		ipVersion = 6
	} else {
		ipVersion = 4
	}
	createOpts := subnets.CreateOpts{
		Name:        LbProvSubnetName,
		Description: LbProvSubnetDescription,
		NetworkID:   providerNetwork.ID,
		TenantID:    providerNetwork.TenantID,
		CIDR:        networkParameters.ProviderCIDR.String(),
		IPVersion:   gophercloud.IPVersion(ipVersion),
		AllocationPools: []subnets.AllocationPool{
			{
				Start: networkParameters.ProviderAllocationStart.String(),
				End:   networkParameters.ProviderAllocationEnd.String(),
			},
		},
		GatewayIP: &gatewayIP,
	}
	return ensureSubnet(ctx, client, ipVersion, createOpts, log)
}

func ensureProvNetwork(ctx context.Context, client *gophercloud.ServiceClient, netDetails *octaviav1.OctaviaLbMgmtNetworks, serviceTenantID string, log *logr.Logger) (
	*networks.Network, error) {
	_, err := getNetwork(ctx, client, LbProvNetName, serviceTenantID)
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
	provNet, err := ensureNetworkExt(ctx, client, createOpts, log, serviceTenantID)
	if err != nil {
		return nil, err
	}

	// Creating an external network adds a RBAC rule to allow all the tenants to use the network.
	// Update this rule to make it accessible only by the owner of the network.
	// This also fixes the already existing network after an update
	listOpts := rbacpolicies.ListOpts{
		TenantID:     serviceTenantID,
		ObjectID:     provNet.ID,
		TargetTenant: "*",
	}
	allPages, err := rbacpolicies.List(client, listOpts).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	allRBACPolicies, err := rbacpolicies.ExtractRBACPolicies(allPages)
	if err != nil {
		return nil, err
	}

	for _, rbacpolicy := range allRBACPolicies {
		updateOpts := rbacpolicies.UpdateOpts{
			TargetTenant: serviceTenantID,
		}

		_, err := rbacpolicies.Update(ctx, client, rbacpolicy.ID, updateOpts).Extract()
		if err != nil {
			log.Error(err, fmt.Sprintf("Cannot update RBAC policy %s", rbacpolicy.ID))
		}
	}

	return provNet, nil
}

func ensureLbMgmtSubnetRoutes(
	ctx context.Context,
	client *gophercloud.ServiceClient,
	tenantSubnet *subnets.Subnet,
	networkParameters *NetworkParameters,
	tenantRouterPort *ports.Port,
) error {
	if len(tenantSubnet.HostRoutes) == 0 ||
		tenantSubnet.HostRoutes[0].NextHop != tenantRouterPort.FixedIPs[0].IPAddress {
		hostRoutes := []subnets.HostRoute{
			{
				DestinationCIDR: networkParameters.ProviderCIDR.String(),
				NextHop:         tenantRouterPort.FixedIPs[0].IPAddress,
			},
		}
		updateOpts := subnets.UpdateOpts{
			HostRoutes: &hostRoutes,
		}
		_, err := subnets.Update(ctx, client, tenantSubnet.ID, updateOpts).Extract()
		if err != nil {
			return err
		}
	}

	return nil
}

func ensureLbMgmtSubnet(
	ctx context.Context,
	client *gophercloud.ServiceClient,
	availabilityZone *string,
	tenantNetwork *networks.Network,
	networkParameters *NetworkParameters,
	log *logr.Logger,
) (*subnets.Subnet, error) {
	var ipVersion int

	var subnetName string
	var description string
	if availabilityZone == nil {
		subnetName = LbMgmtSubnetName
		description = LbMgmtSubnetDescription
	} else {
		subnetName = fmt.Sprintf(LbMgmtSubnetNameAZ, *availabilityZone)
		description = fmt.Sprintf(LbMgmtSubnetDescriptionAZ, *availabilityZone)
	}

	if networkParameters.TenantCIDR.Addr().Is6() {
		ipVersion = 6
	} else {
		ipVersion = 4
	}

	var createOpts subnets.CreateOpts
	if ipVersion == 6 {
		gatewayIP := LbMgmtSubnetIPv6GatewayIP
		createOpts = subnets.CreateOpts{
			Name:            subnetName,
			Description:     description,
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
		}
	} else {
		gatewayIP := LbMgmtSubnetGatewayIP
		createOpts = subnets.CreateOpts{
			Name:        subnetName,
			Description: description,
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
			GatewayIP: &gatewayIP,
		}
	}
	return ensureSubnet(ctx, client, ipVersion, createOpts, log)
}

func ensureLbMgmtNetwork(
	ctx context.Context,
	client *gophercloud.ServiceClient,
	availabilityZone *string,
	networkDetails *octaviav1.OctaviaLbMgmtNetworks,
	serviceTenantID string,
	log *logr.Logger,
) (*networks.Network, error) {
	var networkName string
	var description string
	var azHints []string
	if availabilityZone == nil {
		networkName = LbMgmtNetName
		description = LbMgmtNetDescription
		azHints = networkDetails.AvailabilityZones
	} else {
		networkName = fmt.Sprintf(LbMgmtNetNameAZ, *availabilityZone)
		description = fmt.Sprintf(LbMgmtNetDescriptionAZ, *availabilityZone)
		azHints = []string{*availabilityZone}
	}
	mgmtNetwork, err := getNetwork(ctx, client, networkName, serviceTenantID)
	if err != nil {
		return nil, err
	}

	if networkDetails == nil && mgmtNetwork == nil {
		return nil, fmt.Errorf("%w: \"%s\"", ErrCannotFindNetwork, networkName)
	}

	asu := true
	createOpts := networks.CreateOpts{
		Name:                  networkName,
		Description:           description,
		AdminStateUp:          &asu,
		TenantID:              serviceTenantID,
		AvailabilityZoneHints: azHints,
	}
	mgmtNetwork, err = ensureNetwork(ctx, client, createOpts, log, serviceTenantID)
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
func reconcileRouter(ctx context.Context, client *gophercloud.ServiceClient, router *routers.Router,
	gatewayNetwork *networks.Network,
	gatewaySubnet *subnets.Subnet,
	networkParameters *NetworkParameters,
	log *logr.Logger) (*routers.Router, error) {

	if !router.AdminStateUp {
		return router, fmt.Errorf("%w: %s", ErrRouterNotUp, router.Name)
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
		updatedRouter, err := routers.Update(ctx, client, router.ID, updateInfo).Extract()
		if err != nil {
			return nil, err
		}
		log.Info(fmt.Sprintf("Updated octavia management router %s", router.ID))
		return updatedRouter, nil
	}

	return router, nil
}

// findRouter is a simple helper method...
func findRouter(ctx context.Context, client *gophercloud.ServiceClient, log *logr.Logger) (*routers.Router, error) {
	listOpts := routers.ListOpts{
		Name: LbRouterName,
	}
	allPages, err := routers.List(client, listOpts).AllPages(ctx)
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
func findSecurityGroupRule(ctx context.Context, client *gophercloud.ServiceClient, criteria *rules.ListOpts, log *logr.Logger) (*rules.SecGroupRule, error) {
	//
	// Strip description out of search. While informative, we are not concerned with that field.
	//
	listOpts := *criteria
	listOpts.Description = ""

	allPages, err := rules.List(client, listOpts).AllPages(ctx)

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

func ensureSecurityGroupRules(ctx context.Context, client *gophercloud.ServiceClient, securityGroup *groups.SecGroup, rulesDefinitions []rules.ListOpts, log *logr.Logger) error {
	for _, r := range rulesDefinitions {
		r.TenantID = securityGroup.TenantID
		r.SecGroupID = securityGroup.ID
		r.Direction = "ingress"
		rule, err := findSecurityGroupRule(ctx, client, &r, log)
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
		_, err = rules.Create(ctx, client, createOpts).Extract()
		if err != nil {
			log.Error(err, fmt.Sprintf("ensureSecurityGroupRules: error creating rule %s", r.Description))
		}
	}
	return nil
}

type ensureRules func(ctx context.Context, client *gophercloud.ServiceClient, securityGroup *groups.SecGroup, log *logr.Logger) error

func ensureMgmtRules(ctx context.Context, client *gophercloud.ServiceClient, securityGroup *groups.SecGroup, log *logr.Logger) error {
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
	return ensureSecurityGroupRules(ctx, client, securityGroup, rulesDefinitions, log)
}

func ensureHealthMgrRules(ctx context.Context, client *gophercloud.ServiceClient, securityGroup *groups.SecGroup, log *logr.Logger) error {
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
	return ensureSecurityGroupRules(ctx, client, securityGroup, healthManagerRules, log)
}

func findSecurityGroup(ctx context.Context, client *gophercloud.ServiceClient, tenantID string, groupName string, log *logr.Logger) (*groups.SecGroup, error) {
	listOpts := groups.ListOpts{
		TenantID: tenantID,
	}
	allPages, err := groups.List(client, listOpts).AllPages(ctx)
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
	ctx context.Context,
	client *gophercloud.ServiceClient,
	tenantID string,
	groupName string,
	ruleFn ensureRules,
	log *logr.Logger) (
	string, error) {

	secGroup, err := findSecurityGroup(ctx, client, tenantID, groupName, log)
	if err != nil {
		return "", err
	}
	if secGroup == nil {
		log.Info(fmt.Sprintf("ensureSecurityGroup: security group %s not found, creating...", groupName))
		createOpts := groups.CreateOpts{
			Name:     groupName,
			TenantID: tenantID,
		}
		secGroup, err = groups.Create(ctx, client, createOpts).Extract()
		if err != nil {
			log.Error(err, fmt.Sprintf("ensureLbMgmtSecurityGroup: unable to create security group %s",
				groupName))
			return "", err
		}
	}

	err = ruleFn(ctx, client, secGroup, log)
	if err != nil {
		return "", err
	}
	return secGroup.ID, nil
}

// HandleUnmanagedAmphoraManagementNetwork manages unmanaged amphora management network configurations
func HandleUnmanagedAmphoraManagementNetwork(
	ctx context.Context,
	ns string,
	tenantName string,
	netDetails *octaviav1.OctaviaLbMgmtNetworks,
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
	serviceTenant, err := GetProject(ctx, o, tenantName)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}

	tenantNetworkID := ""
	network, err := getNetwork(ctx, client, LbMgmtNetName, serviceTenant.ID)
	if err == nil && network != nil {
		tenantNetworkID = network.ID
	}

	managementSubnetGateway := ""
	router, err := findRouter(ctx, client, log)
	if err == nil && router != nil {
		if len(router.GatewayInfo.ExternalFixedIPs) > 0 {
			managementSubnetGateway = router.GatewayInfo.ExternalFixedIPs[0].IPAddress
		} else {
			log.Info("No external fixedIP on router %s, skipping", router.Name)
		}
	}

	managementSubnetCIDR := ""
	subnet, err := getSubnet(ctx, client, LbMgmtSubnetName, serviceTenant.ID)
	if err == nil && subnet != nil {
		managementSubnetCIDR = subnet.CIDR
	}

	managementSubnetExtraCIDRs := []string{}
	for _, az := range netDetails.AvailabilityZones {
		subnet, err := getSubnet(ctx, client, fmt.Sprintf(LbMgmtSubnetNameAZ, az), serviceTenant.ID)
		if err == nil && subnet != nil {
			managementSubnetExtraCIDRs = append(managementSubnetExtraCIDRs, subnet.CIDR)
		}
	}

	securityGroupID := ""
	securityGroup, err := findSecurityGroup(ctx, client, serviceTenant.ID, LbMgmtNetworkSecurityGroupName, log)
	if err == nil && securityGroup != nil {
		securityGroupID = securityGroup.ID
	}

	return NetworkProvisioningSummary{
		TenantNetworkID:            tenantNetworkID,
		SecurityGroupID:            securityGroupID,
		ManagementSubnetCIDR:       managementSubnetCIDR,
		ManagementSubnetGateway:    managementSubnetGateway,
		ManagementSubnetExtraCIDRs: managementSubnetExtraCIDRs,
	}, nil
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
	serviceTenant, err := GetProject(ctx, o, tenantName)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}

	lbMgmtSecurityGroupID, err := ensureSecurityGroup(ctx, client, serviceTenant.ID, LbMgmtNetworkSecurityGroupName, ensureMgmtRules, log)
	if err != nil {
		log.Error(err, "Unable to complete configuration of management network security groups, continuing...")
	}
	lbHealthSecurityGroupID, err := ensureSecurityGroup(ctx, client, serviceTenant.ID, LbMgmtHealthManagerSecurityGroupName, ensureHealthMgrRules, log)
	if err != nil {
		log.Error(err, "Unable to complete configuration of management network security groups, continuing...")
	}

	securityGroups := []string{lbMgmtSecurityGroupID, lbHealthSecurityGroupID}

	var tenantNetwork *networks.Network
	var tenantSubnet *subnets.Subnet
	var tenantRouterPort *ports.Port
	tenantNetworkID := ""

	if netDetails.CreateDefaultLbMgmtNetwork {
		tenantNetwork, err = ensureLbMgmtNetwork(ctx, client, nil, netDetails, serviceTenant.ID, log)
		if err != nil {
			return NetworkProvisioningSummary{}, err
		}
		tenantNetworkID = tenantNetwork.ID

		tenantSubnet, err = ensureLbMgmtSubnet(ctx, client, nil, tenantNetwork, networkParameters, log)
		if err != nil {
			return NetworkProvisioningSummary{}, err
		}

		tenantRouterPort, _, err = ensurePort(ctx, client, nil, tenantNetwork, &securityGroups, log)
		if err != nil {
			return NetworkProvisioningSummary{}, err
		}
	}

	adminTenant, err := GetProject(ctx, o, AdminTenant)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}

	_, err = ensureSecurityGroup(ctx, client, adminTenant.ID, LbProvNetworkSecurityGroupName, ensureMgmtRules, log)
	if err != nil {
		log.Error(err, "Unable to complete configuration of octavia provider network security groups, continuing...")
	}
	_, err = ensureSecurityGroup(ctx, client, adminTenant.ID, LbProvHealthManagerSecurityGroupName, ensureHealthMgrRules, log)
	if err != nil {
		log.Error(err, "Unable to complete configuration of octavia provider network security groups, continuing...")
	}

	providerNetwork, err := ensureProvNetwork(ctx, client, netDetails, adminTenant.ID, log)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}

	providerSubnet, err := ensureProvSubnet(ctx, client, providerNetwork, networkParameters, log)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}

	router, err := findRouter(ctx, client, log)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}
	if router != nil {
		log.Info("Router object found, reconciling")
		router, err = reconcileRouter(ctx, client, router, providerNetwork, providerSubnet, networkParameters, log)
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
		router, err = routers.Create(ctx, client, createOpts).Extract()
		if err != nil {
			log.Error(err, "Unable to create router object")
			return NetworkProvisioningSummary{}, err
		}

		if tenantRouterPort != nil {
			interfaceOpts := routers.AddInterfaceOpts{
				PortID: tenantRouterPort.ID,
			}
			_, err := routers.AddInterface(ctx, client, router.ID, interfaceOpts).Extract()
			if err != nil {
				log.Error(err, fmt.Sprintf("Unable to add interface port %s to router %s", tenantRouterPort.ID, router.ID))
			}
		}
	}

	if tenantSubnet != nil {
		// Set route on subnet
		err = ensureLbMgmtSubnetRoutes(ctx, client, tenantSubnet, networkParameters, tenantRouterPort)
		if err != nil {
			log.Error(err, fmt.Sprintf("Unable to set host routes on subnet %s", tenantSubnet.ID))
		}
	}

	managementSubnetAZCIDRs := []string{}
	for az, cidr := range netDetails.AvailabilityZoneCIDRs {
		// Create Management network and subnet for AZ
		network, err := ensureLbMgmtNetwork(ctx, client, &az, netDetails, serviceTenant.ID, log)
		if err != nil {
			return NetworkProvisioningSummary{}, err
		}

		subnetCIDR, err := netip.ParsePrefix(cidr)
		if err != nil {
			return NetworkProvisioningSummary{}, fmt.Errorf("cannot parse CIDR %s for AZ %s: %w", cidr, az, err)
		}
		start, end := GetRangeFromCIDR(subnetCIDR)
		networkAZParameters := NetworkParameters{
			TenantCIDR:            subnetCIDR,
			TenantAllocationStart: start,
			TenantAllocationEnd:   end,
		}
		subnet, err := ensureLbMgmtSubnet(ctx, client, &az, network, &networkAZParameters, log)
		if err != nil {
			return NetworkProvisioningSummary{}, err
		}

		// Create a port for the router, will be the gateway from the subnet to the control plane
		routerPort, created, err := ensurePort(ctx, client, &az, network, &securityGroups, log)
		if err != nil {
			return NetworkProvisioningSummary{}, err
		}

		if created {
			// Plug port into the existing router
			interfaceOpts := routers.AddInterfaceOpts{
				PortID: routerPort.ID,
			}

			_, err = routers.AddInterface(ctx, client, router.ID, interfaceOpts).Extract()
			if err != nil {
				log.Error(err, fmt.Sprintf("Unable to add interface port %s to router %s", routerPort.ID, router.ID))
			}
		}

		// Set route to the control plane
		err = ensureLbMgmtSubnetRoutes(ctx, client, subnet, networkParameters, routerPort)
		if err != nil {
			log.Error(err, fmt.Sprintf("Unable to set host routes on subnet %s", subnet.ID))
		}

		managementSubnetAZCIDRs = append(managementSubnetAZCIDRs, subnetCIDR.String())
	}

	managementSubnetCIDR := ""
	if networkParameters.TenantCIDR.IsValid() {
		managementSubnetCIDR = networkParameters.TenantCIDR.String()
	}

	return NetworkProvisioningSummary{
		TenantNetworkID:            tenantNetworkID,
		SecurityGroupID:            lbMgmtSecurityGroupID,
		ManagementSubnetCIDR:       managementSubnetCIDR,
		ManagementSubnetGateway:    networkParameters.ProviderGateway.String(),
		ManagementSubnetExtraCIDRs: managementSubnetAZCIDRs,
	}, nil
}

// GetPredictableIPAM returns a struct describing the available IP range. If the
// IP pool size does not fit in given networkParameters CIDR it will return an
// error instead.
func GetPredictableIPAM(networkParameters *NetworkParameters) (*NADIpam, error) {
	predParams := &NADIpam{}
	predParams.CIDR = networkParameters.ProviderCIDR
	predParams.RangeStart = networkParameters.ProviderAllocationEnd.Next()
	endRange := predParams.RangeStart
	for range LbProvPredictablePoolSize {
		if !predParams.CIDR.Contains(endRange) {
			return nil, fmt.Errorf("%w: %d in %s", ErrPredictableIPAllocation, LbProvPredictablePoolSize, predParams.CIDR)
		}
		endRange = endRange.Next()
	}
	predParams.RangeEnd = endRange
	return predParams, nil
}

// GetNextIP picks the next available IP from the range defined by a NADIpam,
// skipping ones that are already used appear as keys in the currentValues map.
func GetNextIP(predParams *NADIpam, currentValues map[string]bool) (string, error) {
	candidateAddress := predParams.RangeStart
	for alloced := true; alloced; {

		if _, ok := currentValues[candidateAddress.String()]; ok {
			if candidateAddress == predParams.RangeEnd {
				return "", ErrPredictableIPOutOfAddresses
			}
			candidateAddress = candidateAddress.Next()
		} else {
			alloced = false
		}
	}
	currentValues[candidateAddress.String()] = true
	return candidateAddress.String(), nil
}
