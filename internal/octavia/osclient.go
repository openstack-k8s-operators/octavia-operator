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

	keystonev1 "github.com/openstack-k8s-operators/keystone-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	"github.com/openstack-k8s-operators/lib-common/modules/openstack"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GetOpenstackClient returns an openstack admin service client object
func GetOpenstackClient(
	ctx context.Context,
	ns string,
	h *helper.Helper,
) (*openstack.OpenStack, error) {
	keystoneAPI, err := keystonev1.GetKeystoneAPI(ctx, h, ns, map[string]string{})
	if err != nil {
		return nil, err
	}
	o, _, err := GetAdminServiceClient(ctx, h, keystoneAPI)
	if err != nil {
		return nil, err
	}
	return o, nil
}

// GetOpenstackServiceClient returns an openstack service client object
func GetOpenstackServiceClient(
	ctx context.Context,
	instance *octaviav1.Octavia,
	h *helper.Helper,
) (*openstack.OpenStack, error) {
	keystoneAPI, err := keystonev1.GetKeystoneAPI(ctx, h, instance.Namespace, map[string]string{})
	if err != nil {
		return nil, err
	}
	o, _, err := GetServiceClient(ctx, h, instance, keystoneAPI)
	if err != nil {
		return nil, err
	}
	return o, nil
}

// GetOwningOctaviaControllerName - Given a OctaviaHousekeeping, OctaviaHealthmanager or OctaviaWorker
// object, returning the parent Octavia object that created it (if any)
func GetOwningOctaviaControllerName(instance client.Object) string {
	for _, ownerRef := range instance.GetOwnerReferences() {
		if ownerRef.Kind == "Octavia" {
			return ownerRef.Name
		}
	}

	return ""
}
