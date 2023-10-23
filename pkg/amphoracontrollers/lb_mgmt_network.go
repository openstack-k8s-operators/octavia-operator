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

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	keystonev1 "github.com/openstack-k8s-operators/keystone-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/octavia-operator/pkg/octavia"
)

func ensureLbMgmtSubnet(client *gophercloud.ServiceClient, instance *octaviav1.OctaviaAmphoraController, log *logr.Logger, serviceTenantID string, lbMgmtNetID string) (*subnets.Subnet, error) {
	ipVersion := instance.Spec.LbMgmtNetworks.SubnetIPVersion

	listOpts := subnets.ListOpts{
		Name:      LbMgmtSubnetName,
		NetworkID: lbMgmtNetID,
		TenantID:  serviceTenantID,
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

	var createOpts subnets.CreateOpts
	if ipVersion == 6 {
		gatewayIP := LbMgmtSubnetIPv6GatewayIP
		createOpts = subnets.CreateOpts{
			Name:            LbMgmtSubnetName,
			Description:     LbMgmtSubnetDescription,
			NetworkID:       lbMgmtNetID,
			TenantID:        serviceTenantID,
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
		}
	} else {
		gatewayIP := LbMgmtSubnetGatewayIP
		createOpts = subnets.CreateOpts{
			Name:        LbMgmtSubnetName,
			Description: LbMgmtSubnetDescription,
			NetworkID:   lbMgmtNetID,
			TenantID:    serviceTenantID,
			CIDR:        LbMgmtSubnetCIDR,
			IPVersion:   gophercloud.IPVersion(ipVersion),
			AllocationPools: []subnets.AllocationPool{
				{
					Start: LbMgmtSubnetAllocationPoolStart,
					End:   LbMgmtSubnetAllocationPoolEnd,
				},
			},
			GatewayIP: &gatewayIP,
		}
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

func getLbMgmtNetwork(client *gophercloud.ServiceClient, instance *octaviav1.OctaviaAmphoraController, serviceTenantID string) (*networks.Network, error) {
	listOpts := networks.ListOpts{
		Name:     LbMgmtNetName,
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

func ensureLbMgmtNetwork(client *gophercloud.ServiceClient, instance *octaviav1.OctaviaAmphoraController, log *logr.Logger, serviceTenantID string) (*networks.Network, error) {
	lbMgmtNet, err := getLbMgmtNetwork(client, instance, serviceTenantID)
	if err != nil {
		return nil, err
	}

	asu := true
	createOpts := networks.CreateOpts{
		Name:         LbMgmtNetName,
		Description:  LbMgmtNetDescription,
		AdminStateUp: &asu,
		TenantID:     serviceTenantID,
	}
	if lbMgmtNet == nil {
		log.Info(fmt.Sprintf("Creating Octavia management network \"%s\"", createOpts.Name))
		lbMgmtNet, err = networks.Create(client, createOpts).Extract()
		if err != nil {
			return nil, err
		}
	} else {
		emptyOpts := networks.UpdateOpts{}
		delta := networks.UpdateOpts{}
		if lbMgmtNet.Description != createOpts.Description {
			delta.Description = &createOpts.Description
		}
		if lbMgmtNet.AdminStateUp != *createOpts.AdminStateUp {
			delta.AdminStateUp = createOpts.AdminStateUp
		}
		if delta != emptyOpts {
			log.Info(fmt.Sprintf("Updating Octavia management network \"%s\"", createOpts.Name))
			lbMgmtNet, err = networks.Update(client, lbMgmtNet.ID, delta).Extract()
			if err != nil {
				return nil, err
			}
		}
	}

	_, err = ensureLbMgmtSubnet(client, instance, log, serviceTenantID, lbMgmtNet.ID)
	if err != nil {
		return nil, err
	}

	return lbMgmtNet, nil
}

// EnsureLbMgmtNetworks - ensure that the Octavia management network is created
//
// returns the UUID of the network
func EnsureLbMgmtNetworks(ctx context.Context, instance *octaviav1.OctaviaAmphoraController, log *logr.Logger, helper *helper.Helper) (string, error) {
	keystoneAPI, err := keystonev1.GetKeystoneAPI(ctx, helper, instance.Namespace, map[string]string{})
	if err != nil {
		return "", err
	}
	o, _, err := octavia.GetAdminServiceClient(ctx, helper, keystoneAPI)
	if err != nil {
		return "", err
	}
	client, err := octavia.GetNetworkClient(o)
	if err != nil {
		return "", err
	}
	serviceTenant, err := octavia.GetProject(o, instance.Spec.TenantName)
	if err != nil {
		return "", err
	}
	var network *networks.Network
	if instance.Spec.LbMgmtNetworks.ManageLbMgmtNetworks {
		network, err = ensureLbMgmtNetwork(client, instance, log, serviceTenant.ID)
	} else {
		network, err = getLbMgmtNetwork(client, instance, serviceTenant.ID)
		if network == nil {
			return "", fmt.Errorf("Cannot find network \"%s\"", LbMgmtNetName)
		}
	}
	if err != nil {
		return "", err
	}
	return network.ID, nil
}
