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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	"github.com/gophercloud/gophercloud/v2"
	computeflavors "github.com/gophercloud/gophercloud/v2/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/flavorprofiles"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/flavors"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	"github.com/openstack-k8s-operators/lib-common/modules/openstack"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/octavia-operator/internal/octavia"
)

// OctaviaFlavors -
type OctaviaFlavors struct {
	Name        string
	Description string
	VCPUs       int
	RAM         int
	Disk        int
	RxTxFactor  int
}

// FlavorProfileData -
type FlavorProfileData struct {
	ComputeFlavorID string `json:"compute_flavor,omitempty"`
	AmpImageTag     string `json:"amp_image_tag,omitempty"`
}

var (
	// TODO(gthiemonge) we may consider updating the size of the disk
	// 3GB is fine when enabling log offloading+disabling local disk storage
	// but when using the defaults, the disk can be filled when testing network performances.
	defaultFlavors = []OctaviaFlavors{
		{
			Name:        "amphora",
			Description: "Flavor for Octavia amphora instances (1 vCPU, 1 GB RAM, 3 GB disk, default flavor)",
			VCPUs:       1,
			RAM:         1024,
			Disk:        3,
			RxTxFactor:  1.0,
		}, {
			Name:        "amphora-4vcpus",
			Description: "Flavor for Octavia amphora instances (4 vCPUs, 4 GB RAM, 3 GB disk)",
			VCPUs:       4,
			RAM:         4096,
			Disk:        3,
			RxTxFactor:  1.0,
		},
	}
)

func getAmphoraFlavors(ctx context.Context, computeClient *gophercloud.ServiceClient) (map[string]computeflavors.Flavor, error) {
	// Get Octavia flavors
	listOpts := computeflavors.ListOpts{
		AccessType: computeflavors.AllAccess,
	}
	allPages, err := computeflavors.ListDetail(computeClient, listOpts).AllPages(ctx)
	if err != nil {
		return nil, fmt.Errorf("error listing compute flavors: %w", err)
	}
	allFlavors, err := computeflavors.ExtractFlavors(allPages)
	if err != nil {
		return nil, fmt.Errorf("error extracting compute flavors: %w", err)
	}
	amphoraFlavors := make(map[string]computeflavors.Flavor)
	for _, flavor := range allFlavors {
		if strings.HasPrefix(flavor.Name, "octavia-") {
			amphoraFlavors[flavor.Name] = flavor
		}
	}
	return amphoraFlavors, nil
}

func getOctaviaFlavorProfiles(ctx context.Context, lbClient *gophercloud.ServiceClient) (map[string]flavorprofiles.FlavorProfile, error) {
	listOpts := flavorprofiles.ListOpts{}
	allPages, err := flavorprofiles.List(lbClient, listOpts).AllPages(ctx)
	if err != nil {
		return nil, fmt.Errorf("error listing flavor profiles: %w", err)
	}
	allFlavorProfiles, err := flavorprofiles.ExtractFlavorProfiles(allPages)
	if err != nil {
		return nil, fmt.Errorf("error extracting flavor profiles: %w", err)
	}
	flavorProfiles := make(map[string]flavorprofiles.FlavorProfile)
	for _, flavorProfile := range allFlavorProfiles {
		flavorProfiles[flavorProfile.Name] = flavorProfile
	}
	return flavorProfiles, nil
}

func getOctaviaFlavors(ctx context.Context, lbClient *gophercloud.ServiceClient) (map[string]flavors.Flavor, error) {
	listOpts := flavors.ListOpts{}
	allPages, err := flavors.List(lbClient, listOpts).AllPages(ctx)
	if err != nil {
		return nil, fmt.Errorf("error listing flavors: %w", err)
	}
	allFlavors, err := flavors.ExtractFlavors(allPages)
	if err != nil {
		return nil, fmt.Errorf("error extracting flavors: %w", err)
	}
	flavors := make(map[string]flavors.Flavor)
	for _, flavor := range allFlavors {
		flavors[flavor.Name] = flavor
	}
	return flavors, nil
}

func ensureFlavors(ctx context.Context, osclient *openstack.OpenStack, log *logr.Logger, instance *octaviav1.OctaviaAmphoraController) (string, error) {
	computeClient, err := octavia.GetComputeClient(osclient)
	if err != nil {
		return "", fmt.Errorf("error getting compute client: %w", err)
	}

	lbClient, err := octavia.GetLoadBalancerClient(osclient)
	if err != nil {
		return "", fmt.Errorf("error getting loadbalancer client: %w", err)
	}

	amphoraFlavors, err := getAmphoraFlavors(ctx, computeClient)
	if err != nil {
		return "", fmt.Errorf("error getting amphora flavors: %w", err)
	}

	isPublic := false
	flavorsCreateOpts := []computeflavors.CreateOpts{}
	for _, defaultFlavor := range defaultFlavors {
		flavorsCreateOpts = append(flavorsCreateOpts, computeflavors.CreateOpts{
			Name:        fmt.Sprintf("octavia-%s", defaultFlavor.Name),
			Description: defaultFlavor.Description,
			VCPUs:       defaultFlavor.VCPUs,
			RAM:         defaultFlavor.RAM,
			Disk:        gophercloud.IntToPointer(defaultFlavor.Disk),
			RxTxFactor:  float64(defaultFlavor.RxTxFactor),
			IsPublic:    &isPublic,
		})
	}
	for _, flavor := range instance.Spec.AmphoraCustomFlavors {
		rxTxFactor := 1.0
		if flavor.RxTxFactor != "" {
			if rxTxFactor, err = strconv.ParseFloat(flavor.RxTxFactor, 64); err != nil {
				return "", err
			}
		}
		flavorsCreateOpts = append(flavorsCreateOpts, computeflavors.CreateOpts{
			Name:        fmt.Sprintf("octavia-%s", flavor.Name),
			Description: flavor.Description,
			VCPUs:       flavor.VCPUs,
			RAM:         flavor.RAM,
			Disk:        gophercloud.IntToPointer(flavor.Disk),
			RxTxFactor:  rxTxFactor,
			IsPublic:    &isPublic,
		})
	}

	// Select the first flavor as the default flavor
	defaultFlavorID := ""
	defaultFlavorName := flavorsCreateOpts[0].Name

	// Default flavor already exists, get its ID
	if flavor, ok := amphoraFlavors[defaultFlavorName]; ok {
		defaultFlavorID = flavor.ID
	}

	// Create missing compute flavors
	for idx, flavorOpts := range flavorsCreateOpts {
		if _, ok := amphoraFlavors[flavorOpts.Name]; !ok {
			log.Info(fmt.Sprintf("Creating Amphora flavor \"%s\"", flavorOpts.Name))
			flavor, err := computeflavors.Create(ctx, computeClient, flavorOpts).Extract()
			if err != nil {
				return "", fmt.Errorf("error creating amphora flavor \"%s\": %w", flavorOpts.Name, err)
			}
			amphoraFlavors[flavorOpts.Name] = *flavor
			if idx == 0 {
				defaultFlavorID = flavor.ID
			}
		}
	}

	// Get Octavia FlavorProfiles and Flavors
	flavorProfileMap, err := getOctaviaFlavorProfiles(ctx, lbClient)
	if err != nil {
		return "", fmt.Errorf("error getting flavor profiles: %w", err)
	}

	flavorMap, err := getOctaviaFlavors(ctx, lbClient)
	if err != nil {
		return "", fmt.Errorf("error getting flavors: %w", err)
	}

	// Update path for OSPRH-17186
	// if the amp_image_tag is an empty string, it's a bug:
	// - delete the associated flavors and flavorprofiles
	// - remove them from the maps so they can be recreated with the correct JSON data
	for _, flavorProfile := range flavorProfileMap {
		if strings.Contains(flavorProfile.FlavorData, "\"amp_image_tag\":\"\"") {
			flavorName := flavorProfile.Name

			if flavor, ok := flavorMap[flavorName]; ok {
				err := flavors.Delete(ctx, lbClient, flavor.ID).ExtractErr()
				if err != nil {
					log.Info("Cannot delete flavor %s (%s), skipping.", flavorName, flavor.ID)
					continue
				}
				delete(flavorMap, flavorName)
			}

			err = flavorprofiles.Delete(ctx, lbClient, flavorProfile.ID).ExtractErr()
			if err != nil {
				log.Info("Cannot delete flavorprofile %s (%s), skipping.", flavorName, flavorProfile.ID)
				continue
			}
			delete(flavorProfileMap, flavorName)
		}
	}

	flavorSuccess := false
	for _, flavorOpts := range flavorsCreateOpts {
		// Create FlavorProfiles if they don't exist

		name := strings.TrimPrefix(flavorOpts.Name, "octavia-")

		if _, ok := flavorProfileMap[name]; !ok {
			flavorProfileData := FlavorProfileData{
				ComputeFlavorID: amphoraFlavors[flavorOpts.Name].ID,
			}

			if amphoraFlavors[flavorOpts.Name].VCPUs > 1 {
				flavorProfileData.AmpImageTag = octavia.AmphoraImageVertTag
			}

			fpDataJSON, err := json.Marshal(flavorProfileData)
			if err != nil {
				return "", err
			}
			flavorProfileCreateOpts := flavorprofiles.CreateOpts{
				Name:         name,
				ProviderName: "amphora",
				FlavorData:   string(fpDataJSON),
			}

			log.Info(fmt.Sprintf("Creating Octavia flavor profile \"%s\"", flavorProfileCreateOpts.Name))
			fp, err := flavorprofiles.Create(ctx, lbClient, flavorProfileCreateOpts).Extract()
			if err != nil {
				log.Info(fmt.Sprintf("Warning: Could not create flavor profile. "+
					"Amphora image might be missing or not "+
					"tagged correctly. Skipping configuration of octavia "+
					"flavor profile %s and octavia flavor %s.",
					flavorProfileCreateOpts.Name, name))
				continue
			}
			flavorProfileMap[fp.Name] = *fp
		}

		// Create Flavors if they don't exist
		if _, ok := flavorMap[name]; !ok {
			flavorCreateOpts := flavors.CreateOpts{
				Name:            name,
				Description:     flavorOpts.Description,
				FlavorProfileId: flavorProfileMap[name].ID,
				Enabled:         true,
			}
			log.Info(fmt.Sprintf("Creating Octavia flavor \"%s\"", flavorCreateOpts.Name))
			_, err := flavors.Create(ctx, lbClient, flavorCreateOpts).Extract()
			if err != nil {
				return "", fmt.Errorf("error creating flavor \"%s\": %w", flavorCreateOpts.Name, err)
			}
		}
		flavorSuccess = true
	}
	if !flavorSuccess {
		return "", octavia.ErrOctaviaFlavorsConfig
	}
	return defaultFlavorID, nil
}

// EnsureFlavors - enable that the Nova flavors for the amphora VMs are created
//
// returns the UUID of the default Nova flavor
func EnsureFlavors(ctx context.Context, instance *octaviav1.OctaviaAmphoraController, log *logr.Logger, helper *helper.Helper) (string, error) {
	osclient, err := octavia.GetOpenstackClient(ctx, instance.Namespace, helper)
	if err != nil {
		return "", fmt.Errorf("error while getting a service client when creating flavors: %w", err)
	}

	defaultNovaFlavorID, err := ensureFlavors(ctx, osclient, log, instance)
	if err != nil {
		return "", fmt.Errorf("error while creating flavors: %w", err)
	}

	return defaultNovaFlavorID, nil
}
