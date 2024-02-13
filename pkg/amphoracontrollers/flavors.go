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
	"strings"

	"github.com/go-logr/logr"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/flavors"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	"github.com/openstack-k8s-operators/lib-common/modules/openstack"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/octavia-operator/pkg/octavia"
)

func ensureNovaFlavors(osclient *openstack.OpenStack, log *logr.Logger) (string, error) {
	client, err := octavia.GetComputeClient(osclient)
	if err != nil {
		return "", err
	}

	// Get Octavia flavors
	listOpts := flavors.ListOpts{
		AccessType: flavors.AllAccess,
	}
	allPages, err := flavors.ListDetail(client, listOpts).AllPages()
	if err != nil {
		return "", err
	}
	allFlavors, err := flavors.ExtractFlavors(allPages)
	if err != nil {
		return "", err
	}
	amphoraFlavors := make(map[string]flavors.Flavor)
	for _, flavor := range allFlavors {
		if strings.HasPrefix(flavor.Name, "octavia-") {
			amphoraFlavors[flavor.Name] = flavor
		}
	}

	isPublic := false
	// TODO(gthiemonge) we may consider updating the size of the disk
	// 3GB is fine when enabling log offloading+disabling local disk storage
	// but when using the defaults, the disk can be filled when testing network performances.
	defaultFlavorsCreateOpts := []flavors.CreateOpts{
		{
			Name:        "octavia-amphora",
			Description: "Flavor for Octavia amphora instances (1 vCPU, 1 GB RAM, 3 GB disk, default flavor)",
			VCPUs:       1,
			RAM:         1024,
			Disk:        gophercloud.IntToPointer(3),
			RxTxFactor:  1.0,
			IsPublic:    &isPublic,
		}, {
			Name:        "octavia-amphora-4vcpus",
			Description: "Flavor for Octavia amphora instances (4 vCPUs, 4 GB RAM, 3 GB disk)",
			VCPUs:       4,
			RAM:         4096,
			Disk:        gophercloud.IntToPointer(3),
			RxTxFactor:  1.0,
			IsPublic:    &isPublic,
		},
	}
	defaultFlavorID := ""
	defaultFlavorName := defaultFlavorsCreateOpts[0].Name

	// Default flavor already exists, get its ID
	if flavor, ok := amphoraFlavors[defaultFlavorName]; ok {
		defaultFlavorID = flavor.ID
	}

	// Create missing flavors
	for idx, defaultFlavorOpts := range defaultFlavorsCreateOpts {
		if _, ok := amphoraFlavors[defaultFlavorOpts.Name]; !ok {
			log.Info(fmt.Sprintf("Creating Amphora flavor \"%s\"", defaultFlavorOpts.Name))
			flavor, err := flavors.Create(client, defaultFlavorOpts).Extract()
			if err != nil {
				return "", err
			}
			if idx == 0 {
				defaultFlavorID = flavor.ID
			}
		}
	}

	return defaultFlavorID, nil
}

// EnsureFlavors - enable that the Nova flavors for the amphora VMs are created
//
// returns the UUID of the default Nova flavor
func EnsureFlavors(ctx context.Context, instance *octaviav1.OctaviaAmphoraController, log *logr.Logger, helper *helper.Helper) (string, error) {
	osclient, err := GetOpenstackClient(ctx, instance, helper)
	if err != nil {
		return "", err
	}

	defaultNovaFlavorID, err := ensureNovaFlavors(osclient, log)
	if err != nil {
		return "", err
	}

	// TODO(gthiemonge) Create Octavia flavorprofiles and flavors when gophercloud support them

	return defaultNovaFlavorID, nil
}
