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

package amphoracontrollers

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/external"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/provider"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/octavia-operator/pkg/octavia"
)

type NetworkProvisioningSummary struct {
	TenantNetworkID    string
	TenantSubnetID     string
	TenantRouterPortID string
	ProviderNetworkID  string
	RouterID           string
}

//
// TODO(beagles) we need to decide what, if any of the results of these methods we want to expose in the controller's
// status.
//

func findPort(client *gophercloud.ServiceClient, portName string, networkID string, subnetID string, ipAddress string, log *logr.Logger) (*ports.Port, error) {
	listOpts := ports.ListOpts{
		Name:      portName,
		NetworkID: networkID,
		FixedIPs: []ports.FixedIPOpts{
			{
				SubnetID:  subnetID,
				IPAddress: ipAddress,
			},
		},
	}
	allPages, err := ports.List(client, listOpts).AllPages()
	if err != nil {
		return nil, err
	}

	allPorts, err := ports.ExtractPorts(allPages)
	if err != nil {
		return nil, err
	}
	if len(allPorts) > 0 {
		return &allPorts[0], nil
	}
	return nil, nil
}

func ensurePort(client *gophercloud.ServiceClient, tenantNetwork *networks.Network, tenantSubnet *subnets.Subnet, log *logr.Logger) (*ports.Port, error) {
	ipAddress := LbMgmtRouterPortIPPv4
	if tenantSubnet.IPVersion == 6 {
		ipAddress = LbMgmtRouterPortIPPv6
	}

	p, err := findPort(client, LbMgmtRouterPortName, tenantNetwork.ID, tenantSubnet.ID, ipAddress, log)
	if err != nil {
		return nil, err
	}
	if p != nil {
		//
		// TODO(beagles): reconcile port properties? Is there anything to do? Security groups possibly.
		//
		return p, nil
	}
	asu := true
	createOpts := ports.CreateOpts{
		Name:         LbMgmtRouterPortName,
		AdminStateUp: &asu,
		NetworkID:    tenantNetwork.ID,
		FixedIPs: []ports.FixedIPOpts{
			{
				SubnetID:  tenantSubnet.ID,
				IPAddress: ipAddress,
			},
		},
	}
	p, err = ports.Create(client, createOpts).Extract()
	if err != nil {
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
			provider.Segment{
				NetworkType:     "flat",
				PhysicalNetwork: "br-octavia",
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

func ensureProvSubnet(client *gophercloud.ServiceClient, providerNetwork *networks.Network, log *logr.Logger) (
	*subnets.Subnet, error) {
	gatewayIP := LbProvSubnetGatewayIP
	createOpts := subnets.CreateOpts{
		Name:        LbProvSubnetName,
		Description: LbProvSubnetDescription,
		NetworkID:   providerNetwork.ID,
		TenantID:    providerNetwork.TenantID,
		CIDR:        LbProvSubnetCIDR,
		IPVersion:   gophercloud.IPVersion(4),
		AllocationPools: []subnets.AllocationPool{
			{
				Start: LbProvSubnetAllocationPoolStart,
				End:   LbProvSubnetAllocationPoolEnd,
			},
		},
		GatewayIP: &gatewayIP,
	}
	return ensureSubnet(client, 4, createOpts, log)
}

func ensureProvNetwork(client *gophercloud.ServiceClient, serviceTenantID string, log *logr.Logger) (
	*networks.Network, error) {
	provNet, err := getNetwork(client, LbProvNetName, serviceTenantID)
	if err != nil {
		return nil, err
	}

	asu := true
	createOpts := networks.CreateOpts{
		Name:         LbProvNetName,
		Description:  LbProvNetDescription,
		AdminStateUp: &asu,
		TenantID:     serviceTenantID,
	}
	provNet, err = ensureNetworkExt(client, createOpts, log, serviceTenantID)
	if err != nil {
		return nil, err
	}

	return provNet, nil
}

func ensureLbMgmtSubnet(
	client *gophercloud.ServiceClient,
	networkDetails *octaviav1.OctaviaLbMgmtNetworks,
	tenantNetwork *networks.Network,
	log *logr.Logger,
) (*subnets.Subnet, error) {
	ipVersion := networkDetails.SubnetIPVersion

	var createOpts subnets.CreateOpts
	if ipVersion == 6 {
		gatewayIP := LbMgmtSubnetIPv6GatewayIP
		createOpts = subnets.CreateOpts{
			Name:            LbMgmtSubnetName,
			Description:     LbMgmtSubnetDescription,
			NetworkID:       tenantNetwork.ID,
			TenantID:        tenantNetwork.TenantID,
			CIDR:            LbMgmtSubnetIPv6CIDR,
			IPVersion:       gophercloud.IPVersion(ipVersion),
			IPv6AddressMode: LbMgmtSubnetIPv6AddressMode,
			IPv6RAMode:      LbMgmtSubnetIPv6RAMode,
			AllocationPools: []subnets.AllocationPool{
				{
					Start: LbMgmtSubnetIPv6AllocationPoolStart,
					End:   LbMgmtSubnetIPv6AllocationPoolEnd,
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
			CIDR:        LbMgmtSubnetCIDR,
			IPVersion:   gophercloud.IPVersion(ipVersion),
			AllocationPools: []subnets.AllocationPool{
				{
					Start: LbMgmtSubnetAllocationPoolStart,
					End:   LbMgmtSubnetAllocationPoolEnd,
				},
			},
			HostRoutes: []subnets.HostRoute{
				{
					DestinationCIDR: LbProvSubnetCIDR,
					NextHop:         LbMgmtRouterPortIPPv4,
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
		Name:         LbMgmtNetName,
		Description:  LbMgmtNetDescription,
		AdminStateUp: &asu,
		TenantID:     serviceTenantID,
	}
	mgmtNetwork, err = ensureNetwork(client, createOpts, log, serviceTenantID)
	if err != nil {
		return nil, err
	}

	return mgmtNetwork, nil
}

func externalFixedIPs(subnetID string) []routers.ExternalFixedIP {
	ips := []routers.ExternalFixedIP{
		routers.ExternalFixedIP{
			IPAddress: LbRouterFixedIPAddress,
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
	tenantRouterPort *ports.Port,
	log *logr.Logger) (*routers.Router, error) {

	if !router.AdminStateUp {
		return router, fmt.Errorf("Router %s is not up", router.Name)
	}

	// TODO(beagles) check the status string.
	// if router.Status == ?

	needsUpdate := false
	updateInfo := routers.UpdateOpts{}
	enableSNAT := false
	fixedIPs := externalFixedIPs(gatewaySubnet.ID)

	//
	// TODO(beagles) we don't care about the other fields right now because we
	// are just going with neutron defaults but in the future we may care about
	// Distributed (oddly HA doesn't seem to be an option)
	//
	gatewayInfo := router.GatewayInfo
	if gatewayNetwork.ID != gatewayInfo.NetworkID || *gatewayInfo.EnableSNAT ||
		compareExternalFixedIPs(gatewayInfo.ExternalFixedIPs, fixedIPs) {
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
		return updatedRouter, nil
	}

	return router, nil
}

// findRouter is a simple helper method...
func findRouter(client *gophercloud.ServiceClient, tenantID string) (*routers.Router, error) {
	listOpts := routers.ListOpts{
		Name:     LbRouterName,
		TenantID: tenantID,
	}
	allPages, err := routers.List(client, listOpts).AllPages()
	if err != nil {
		return nil, err
	}
	allRouters, err := routers.ExtractRouters(allPages)
	if err != nil {
		return nil, err
	}
	if len(allRouters) > 0 {
		return &allRouters[0], nil
	}
	return nil, nil
}

// EnsureAmphoraManagementNetwork - retrieve, create and reconcile the Octavia management network for the in cluster link to the
// management tenant network.
func EnsureAmphoraManagementNetwork(
	ctx context.Context,
	ns string,
	tenantName string,
	netDetails *octaviav1.OctaviaLbMgmtNetworks,
	log *logr.Logger,
	helper *helper.Helper,
) (NetworkProvisioningSummary, error) {
	o, err := octavia.GetOpenstackClient(ctx, ns, helper)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}
	client, err := octavia.GetNetworkClient(o)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}
	serviceTenant, err := octavia.GetProject(o, tenantName)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}

	tenantNetwork, err := ensureLbMgmtNetwork(client, netDetails, serviceTenant.ID, log)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}
	tenantSubnet, err := ensureLbMgmtSubnet(client, netDetails, tenantNetwork, log)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}
	tenantRouterPort, err := ensurePort(client, tenantNetwork, tenantSubnet, log)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}

	providerNetwork, err := ensureProvNetwork(client, serviceTenant.ID, log)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}

	providerSubnet, err := ensureProvSubnet(client, providerNetwork, log)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}

	router, err := findRouter(client, serviceTenant.ID)
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}
	if router != nil {
		router, err = reconcileRouter(client, router, providerNetwork, providerSubnet,
			tenantRouterPort, log)
		if err != nil {
			return NetworkProvisioningSummary{}, err
		}
		log.Info(fmt.Sprintf("Reconciled router %s (%s)", router.Name, router.ID))
	} else {
		enableSNAT := false
		gatewayInfo := routers.GatewayInfo{
			NetworkID:        providerNetwork.ID,
			EnableSNAT:       &enableSNAT,
			ExternalFixedIPs: externalFixedIPs(providerSubnet.ID),
		}
		adminStateUp := true
		createOpts := routers.CreateOpts{
			Name:         LbRouterName,
			AdminStateUp: &adminStateUp,
			GatewayInfo:  &gatewayInfo,
		}
		router, err = routers.Create(client, createOpts).Extract()
		if err != nil {
			return NetworkProvisioningSummary{}, err
		}
	}
	interfaceOpts := routers.AddInterfaceOpts{
		PortID: tenantRouterPort.ID,
	}
	_, err = routers.AddInterface(client, router.ID, interfaceOpts).Extract()
	if err != nil {
		return NetworkProvisioningSummary{}, err
	}
	return NetworkProvisioningSummary{
		TenantNetworkID:    tenantNetwork.ID,
		TenantSubnetID:     tenantSubnet.ID,
		TenantRouterPortID: tenantRouterPort.ID,
		ProviderNetworkID:  providerNetwork.ID,
		RouterID:           router.ID,
	}, nil
}
