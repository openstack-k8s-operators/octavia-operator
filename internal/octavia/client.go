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
	"net/url"
	"time"

	"github.com/go-logr/logr"
	"github.com/gophercloud/gophercloud/v2"
	gophercloudopenstack "github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/domains"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/projects"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/users"
	keystonev1 "github.com/openstack-k8s-operators/keystone-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/lib-common/modules/common/endpoint"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	"github.com/openstack-k8s-operators/lib-common/modules/common/secret"
	"github.com/openstack-k8s-operators/lib-common/modules/common/tls"
	"github.com/openstack-k8s-operators/lib-common/modules/openstack"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
)

// ClientType defines the type of OpenStack client configuration
type ClientType int

const (
	// AdminClient represents an administrative OpenStack client configuration
	AdminClient ClientType = iota
	// ServiceClient represents a service-level OpenStack client configuration
	ServiceClient ClientType = iota
)

// ClientConfig holds the configuration parameters for OpenStack client connections
type ClientConfig struct {
	User             string
	TenantName       string
	TenantDomainName string
	Region           string
	Secret           string
	Selector         string
}

func getClientConfig(
	clientType ClientType,
	keystoneAPI *keystonev1.KeystoneAPI,
	octavia *octaviav1.Octavia,
) (ClientConfig, error) {
	switch clientType {
	case AdminClient:
		return ClientConfig{
			User:             keystoneAPI.Spec.AdminUser,
			TenantName:       keystoneAPI.Spec.AdminProject,
			TenantDomainName: "Default",
			Region:           keystoneAPI.Spec.Region,
			Secret:           keystoneAPI.Spec.Secret,
			Selector:         keystoneAPI.Spec.PasswordSelectors.Admin,
		}, nil
	case ServiceClient:
		if octavia == nil {
			return ClientConfig{}, ErrServiceClientConfigNilInstance
		}
		return ClientConfig{
			User:             octavia.Spec.ServiceUser,
			TenantName:       octavia.Spec.TenantName,
			TenantDomainName: octavia.Spec.TenantDomainName,
			Region:           keystoneAPI.Spec.Region,
			Secret:           octavia.Spec.Secret,
			Selector:         octavia.Spec.PasswordSelectors.Service,
		}, nil
	}

	return ClientConfig{}, fmt.Errorf("%w: %+v", ErrInvalidClientType, clientType)
}

func getClient(
	ctx context.Context,
	h *helper.Helper,
	clientConfig ClientConfig,
	keystoneAPI *keystonev1.KeystoneAPI,
) (*openstack.OpenStack, ctrl.Result, error) {
	// get internal endpoint as authurl from keystone instance
	authURL, err := keystoneAPI.GetEndpoint(endpoint.EndpointInternal)
	if err != nil {
		return nil, ctrl.Result{}, err
	}

	parsedAuthURL, err := url.Parse(authURL)
	if err != nil {
		return nil, ctrl.Result{}, err
	}

	tlsConfig := &openstack.TLSConfig{}
	if parsedAuthURL.Scheme == "https" {
		caCert, ctrlResult, err := secret.GetDataFromSecret(
			ctx,
			h,
			keystoneAPI.Spec.TLS.CaBundleSecretName,
			time.Duration(10)*time.Second,
			tls.InternalCABundleKey)
		if err != nil {
			return nil, ctrl.Result{}, err
		}
		if (ctrlResult != ctrl.Result{}) {
			return nil, ctrl.Result{}, fmt.Errorf("%w: %s", ErrCABundleSecretNotFound, keystoneAPI.Spec.TLS.CaBundleSecretName)
		}

		tlsConfig = &openstack.TLSConfig{
			CACerts: []string{
				caCert,
			},
		}
	}

	// get the password of the admin user from Spec.Secret
	// using PasswordSelectors.Admin
	authPassword, ctrlResult, err := secret.GetDataFromSecret(
		ctx,
		h,
		clientConfig.Secret,
		time.Duration(10)*time.Second,
		clientConfig.Selector)
	if err != nil {
		return nil, ctrl.Result{}, err
	}
	if (ctrlResult != ctrl.Result{}) {
		// TODO(gthiemonge) callers are ignoring these return values
		// It means that this function can return a nil client when ketystone is not fully initialized
		return nil, ctrlResult, nil
	}

	authOpts := openstack.AuthOpts{
		AuthURL:  authURL,
		Username: clientConfig.User,
		Password: authPassword,
		// The Domain of the user is always Default
		DomainName: "Default",
		Region:     clientConfig.Region,
		TLS:        tlsConfig,
	}

	// gophercloud doesn't support passing the tenant domain name as a string
	// when using a different domain for the User and the Project
	// it requires:
	// - authOpts.DomainName to be the domain of the user
	// - authOpts.TenantID to be the ID of the project in the other domain
	if clientConfig.TenantDomainName != "Default" {
		adminClient, _, err := GetAdminServiceClient(ctx, h, keystoneAPI)
		if err != nil {
			return nil, ctrl.Result{}, err
		}
		project, err := getProjectWithDomain(ctx, adminClient, clientConfig.TenantName, clientConfig.TenantDomainName)
		if err != nil {
			return nil, ctrl.Result{}, err
		}
		authOpts.TenantID = project.ID
	} else {
		authOpts.TenantName = clientConfig.TenantName
	}

	os, err := openstack.NewOpenStack(
		ctx,
		h.GetLogger(),
		authOpts,
	)
	if err != nil {
		return nil, ctrl.Result{}, err
	}

	return os, ctrl.Result{}, nil
}

// GetAdminServiceClient - get a client for the "admin" tenant
func GetAdminServiceClient(
	ctx context.Context,
	h *helper.Helper,
	keystoneAPI *keystonev1.KeystoneAPI,
) (*openstack.OpenStack, ctrl.Result, error) {
	clientConfig, err := getClientConfig(AdminClient, keystoneAPI, nil)
	if err != nil {
		return nil, ctrl.Result{}, err
	}
	return getClient(ctx, h, clientConfig, keystoneAPI)
}

// GetServiceClient - Get a client for the "service" tenant
func GetServiceClient(
	ctx context.Context,
	h *helper.Helper,
	octavia *octaviav1.Octavia,
	keystoneAPI *keystonev1.KeystoneAPI,
) (*openstack.OpenStack, ctrl.Result, error) {
	clientConfig, err := getClientConfig(ServiceClient, keystoneAPI, octavia)
	if err != nil {
		return nil, ctrl.Result{}, err
	}
	return getClient(ctx, h, clientConfig, keystoneAPI)
}

func getDomain(
	ctx context.Context,
	openstack *openstack.OpenStack,
	domainName string,
) (*domains.Domain, error) {
	allPages, err := domains.List(
		openstack.GetOSClient(),
		domains.ListOpts{
			Name: domainName,
		}).AllPages(ctx)
	if err != nil {
		return nil, err
	}
	allDomains, err := domains.ExtractDomains(allPages)
	if err != nil {
		return nil, err
	}
	if len(allDomains) == 0 {
		return nil, fmt.Errorf("%w: \"%s\"", ErrCannotFindDomain, domainName)
	}
	return &allDomains[0], nil

}

func getProjectWithDomain(
	ctx context.Context,
	openstack *openstack.OpenStack,
	projectName string,
	domainName string,
) (*projects.Project, error) {
	domain, err := getDomain(ctx, openstack, domainName)
	if err != nil {
		return nil, err
	}
	allPages, err := projects.List(
		openstack.GetOSClient(),
		projects.ListOpts{
			Name:     projectName,
			DomainID: domain.ID,
		}).AllPages(ctx)
	if err != nil {
		return nil, err
	}
	allProjects, err := projects.ExtractProjects(allPages)
	if err != nil {
		return nil, err
	}
	if len(allProjects) == 0 {
		return nil, fmt.Errorf("%w: \"%s\" in domain \"%s\"", ErrCannotFindProjectInDomain, projectName, domainName)
	}
	return &allProjects[0], nil
}

// GetProject -
func GetProject(ctx context.Context, openstack *openstack.OpenStack, projectName string) (*projects.Project, error) {
	allPages, err := projects.List(openstack.GetOSClient(), projects.ListOpts{Name: projectName}).AllPages(ctx)
	if err != nil {
		return nil, err
	}
	allProjects, err := projects.ExtractProjects(allPages)
	if err != nil {
		return nil, err
	}
	if len(allProjects) == 0 {
		return nil, fmt.Errorf("%w: \"%s\"", ErrCannotFindProject, projectName)
	}
	return &allProjects[0], nil
}

// GetUser -
func GetUser(ctx context.Context, openstack *openstack.OpenStack, userName string) (*users.User, error) {
	allPages, err := users.List(openstack.GetOSClient(), users.ListOpts{Name: userName}).AllPages(ctx)
	if err != nil {
		return nil, err
	}
	allUsers, err := users.ExtractUsers(allPages)
	if err != nil {
		return nil, err
	}
	if len(allUsers) == 0 {
		return nil, fmt.Errorf("%w: \"%s\"", ErrCannotFindUser, userName)
	}
	return &allUsers[0], nil
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
	return gophercloudopenstack.NewImageV2(o.GetOSClient().ProviderClient, endpointOpts)
}

// EnsureUserRoles ensures that the service user has the required roles assigned in the project
func EnsureUserRoles(
	ctx context.Context,
	instance *octaviav1.Octavia,
	log logr.Logger,
	helper *helper.Helper,
) error {
	// keystone operator automatically assigns the right roles when using the
	// service tenant in the Default domain
	if instance.Spec.TenantName == "service" && instance.Spec.TenantDomainName == "Default" {
		return nil
	}

	osclient, err := GetOpenstackClient(ctx, instance.Namespace, helper)
	if err != nil {
		return ErrGettingClientForUserRoles
	}

	project, err := getProjectWithDomain(ctx, osclient, instance.Spec.TenantName, instance.Spec.TenantDomainName)
	if err != nil {
		return fmt.Errorf("%w: \"%s\" in domain \"%s\"", ErrGettingProjectInDomain, instance.Spec.TenantName, instance.Spec.TenantDomainName)
	}

	userDomain := "Default"
	domain, err := getDomain(ctx, osclient, userDomain)
	if err != nil {
		return fmt.Errorf("%w: \"%s\"", ErrGettingDomain, userDomain)
	}

	user, err := osclient.GetUser(ctx, log, instance.Spec.ServiceUser, domain.ID)
	if err != nil {
		return fmt.Errorf("%w: \"%s\" in domain \"%s\"", ErrGettingUserInDomain, instance.Spec.ServiceUser, userDomain)
	}

	roles := []string{"admin", "service"}
	for _, role := range roles {
		err = osclient.AssignUserRole(ctx, log, role, user.ID, project.ID)
		if err != nil {
			return fmt.Errorf("%w: \"%s\" to user \"%s\" in project \"%s\"", ErrSettingUserRole, role, user.Name, project.Name)
		}
	}

	return nil
}
