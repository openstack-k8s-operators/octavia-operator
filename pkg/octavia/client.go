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
	"time"

	"github.com/gophercloud/gophercloud"
	gophercloudopenstack "github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/projects"
	keystonev1 "github.com/openstack-k8s-operators/keystone-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/lib-common/modules/common/endpoint"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	"github.com/openstack-k8s-operators/lib-common/modules/common/secret"
	"github.com/openstack-k8s-operators/lib-common/modules/openstack"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
)

// GetAdminServiceClient - get a client for the "admin" tenant
func GetAdminServiceClient(
	ctx context.Context,
	h *helper.Helper,
	keystoneAPI *keystonev1.KeystoneAPI,
) (*openstack.OpenStack, ctrl.Result, error) {
	// get internal endpoint as authurl from keystone instance
	authURL, err := keystoneAPI.GetEndpoint(endpoint.EndpointInternal)
	if err != nil {
		return nil, ctrl.Result{}, err
	}

	// get the password of the admin user from Spec.Secret
	// using PasswordSelectors.Admin
	authPassword, ctrlResult, err := secret.GetDataFromSecret(
		ctx,
		h,
		keystoneAPI.Spec.Secret,
		time.Duration(10)*time.Second,
		keystoneAPI.Spec.PasswordSelectors.Admin)
	if err != nil {
		return nil, ctrl.Result{}, err
	}
	if (ctrlResult != ctrl.Result{}) {
		return nil, ctrlResult, nil
	}

	authOpts := openstack.AuthOpts{
		AuthURL:    authURL,
		Username:   keystoneAPI.Spec.AdminUser,
		Password:   authPassword,
		TenantName: keystoneAPI.Spec.AdminProject,
		DomainName: "Default",
		Region:     keystoneAPI.Spec.Region,
	}

	os, err := openstack.NewOpenStack(
		h.GetLogger(),
		authOpts,
	)
	if err != nil {
		return nil, ctrl.Result{}, err
	}

	return os, ctrl.Result{}, nil
}

// GetServiceClient - Get a client for the "service" tenant
func GetServiceClient(
	ctx context.Context,
	h *helper.Helper,
	octavia *octaviav1.Octavia,
	keystoneAPI *keystonev1.KeystoneAPI,
) (*openstack.OpenStack, ctrl.Result, error) {
	// get internal endpoint as authurl from keystone instance
	authURL, err := keystoneAPI.GetEndpoint(endpoint.EndpointInternal)
	if err != nil {
		return nil, ctrl.Result{}, err
	}

	// get the password of the admin user from Spec.Secret
	// using PasswordSelectors.Admin
	authPassword, ctrlResult, err := secret.GetDataFromSecret(
		ctx,
		h,
		octavia.Spec.Secret,
		time.Duration(10)*time.Second,
		octavia.Spec.PasswordSelectors.Service)
	if err != nil {
		return nil, ctrl.Result{}, err
	}
	if (ctrlResult != ctrl.Result{}) {
		return nil, ctrlResult, nil
	}

	authOpts := openstack.AuthOpts{
		AuthURL:    authURL,
		Username:   octavia.Spec.ServiceUser,
		Password:   authPassword,
		TenantName: octavia.Spec.TenantName,
		DomainName: "Default",
		Region:     keystoneAPI.Spec.Region,
	}

	os, err := openstack.NewOpenStack(
		h.GetLogger(),
		authOpts,
	)
	if err != nil {
		return nil, ctrl.Result{}, err
	}

	return os, ctrl.Result{}, nil
}

// GetProject -
func GetProject(openstack *openstack.OpenStack, projectName string) (*projects.Project, error) {
	allPages, err := projects.List(openstack.GetOSClient(), projects.ListOpts{Name: projectName}).AllPages()
	if err != nil {
		return nil, err
	}
	allProjects, err := projects.ExtractProjects(allPages)
	if err != nil {
		return nil, err
	}
	if len(allProjects) == 0 {
		return nil, fmt.Errorf("Cannot find project \"%s\"", projectName)
	}
	return &allProjects[0], nil
}

// GetNetworkClient -
func GetNetworkClient(o *openstack.OpenStack) (*gophercloud.ServiceClient, error) {
	endpointOpts := gophercloud.EndpointOpts{
		Region:       o.GetRegion(),
		Availability: gophercloud.AvailabilityInternal,
	}
	return gophercloudopenstack.NewNetworkV2(o.GetOSClient().ProviderClient, endpointOpts)
}

// GetComputeClient -
func GetComputeClient(o *openstack.OpenStack) (*gophercloud.ServiceClient, error) {
	endpointOpts := gophercloud.EndpointOpts{
		Region:       o.GetRegion(),
		Availability: gophercloud.AvailabilityInternal,
	}
	client, err := gophercloudopenstack.NewComputeV2(o.GetOSClient().ProviderClient, endpointOpts)
	if err != nil {
		return nil, err
	}
	// Need at least microversion 2.55 for flavor description
	client.Microversion = "2.55"
	return client, nil
}

// GetLoadBalancerClient -
func GetLoadBalancerClient(o *openstack.OpenStack) (*gophercloud.ServiceClient, error) {
	endpointOpts := gophercloud.EndpointOpts{
		Region:       o.GetRegion(),
		Availability: gophercloud.AvailabilityInternal,
	}
	return gophercloudopenstack.NewLoadBalancerV2(o.GetOSClient().ProviderClient, endpointOpts)
}

// GetImageClient -
func GetImageClient(o *openstack.OpenStack) (*gophercloud.ServiceClient, error) {
	endpointOpts := gophercloud.EndpointOpts{
		Region:       o.GetRegion(),
		Availability: gophercloud.AvailabilityInternal,
	}
	return gophercloudopenstack.NewImageServiceV2(o.GetOSClient().ProviderClient, endpointOpts)
}
