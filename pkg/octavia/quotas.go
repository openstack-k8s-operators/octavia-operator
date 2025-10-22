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

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/quotasets"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/quotas"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	"github.com/openstack-k8s-operators/lib-common/modules/openstack"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
)

func ensureComputeQuotas(
	ctx context.Context,
	log *logr.Logger,
	osclient *openstack.OpenStack,
	serviceTenantID string,
) error {

	computeClient, err := GetComputeClient(osclient)
	if err != nil {
		return err
	}

	// Get the current quotas
	quotaset, err := quotasets.Get(ctx, computeClient, serviceTenantID).Extract()
	if err != nil {
		return err
	}

	updateOpts := quotasets.UpdateOpts{
		RAM:                gophercloud.IntToPointer(-1),
		Cores:              gophercloud.IntToPointer(-1),
		Instances:          gophercloud.IntToPointer(-1),
		ServerGroups:       gophercloud.IntToPointer(-1),
		ServerGroupMembers: gophercloud.IntToPointer(-1),
	}
	// Update only if needed
	if quotaset.RAM != *updateOpts.RAM ||
		quotaset.Cores != *updateOpts.Cores ||
		quotaset.Instances != *updateOpts.Instances ||
		quotaset.ServerGroups != *updateOpts.ServerGroups ||
		quotaset.ServerGroupMembers != *updateOpts.ServerGroupMembers {

		quotaset, err := quotasets.Update(ctx, computeClient, serviceTenantID, updateOpts).Extract()
		if err != nil {
			return err
		}
		log.Info(fmt.Sprintf("Compute quotas updated to %+v", *quotaset))
	}

	return nil
}

func ensureNetworkQuotas(
	ctx context.Context,
	log *logr.Logger,
	osclient *openstack.OpenStack,
	serviceTenantID string,
) error {

	networkClient, err := GetNetworkClient(osclient)
	if err != nil {
		return err
	}

	// Get the current quotas
	quotasInfo, err := quotas.Get(ctx, networkClient, serviceTenantID).Extract()
	if err != nil {
		return err
	}

	updateOpts := quotas.UpdateOpts{
		Port:              gophercloud.IntToPointer(-1),
		SecurityGroup:     gophercloud.IntToPointer(-1),
		SecurityGroupRule: gophercloud.IntToPointer(-1),
	}
	// Update only if needed
	if quotasInfo.Port != *updateOpts.Port ||
		quotasInfo.SecurityGroup != *updateOpts.SecurityGroup ||
		quotasInfo.SecurityGroupRule != *updateOpts.SecurityGroupRule {

		quotasInfo, err := quotas.Update(ctx, networkClient, serviceTenantID, updateOpts).Extract()
		if err != nil {
			return err
		}
		log.Info(fmt.Sprintf("Network quotas updated to %+v", *quotasInfo))
	}

	return nil
}

// EnsureQuotas -- set the quotas for the Octavia project
func EnsureQuotas(
	ctx context.Context,
	instance *octaviav1.Octavia,
	log *logr.Logger,
	helper *helper.Helper,
) error {

	osclient, err := GetOpenstackClient(ctx, instance.Namespace, helper)
	if err != nil {
		return fmt.Errorf("error while getting a service client when set quotas: %w", err)
	}

	serviceTenant, err := GetProject(ctx, osclient, instance.Spec.TenantName)
	if err != nil {
		return fmt.Errorf("error while getting the project %s: %w", instance.Spec.TenantName, err)
	}

	if err := ensureComputeQuotas(ctx, log, osclient, serviceTenant.ID); err != nil {
		return fmt.Errorf("error while setting the compute quotas: %w", err)
	}
	if err := ensureNetworkQuotas(ctx, log, osclient, serviceTenant.ID); err != nil {
		return fmt.Errorf("error while setting the network quotas: %w", err)
	}

	return nil
}
