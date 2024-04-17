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
	"strings"

	"github.com/go-logr/logr"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/imageimport"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/images"
	keystonev1 "github.com/openstack-k8s-operators/keystone-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	"github.com/openstack-k8s-operators/lib-common/modules/openstack"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
)

const (
	AmphoraImageTag     = "amphora-image"
	AmphoraImageVertTag = "amphora-image-vert"
)

type OctaviaAmphoraImage struct {
	ID       string
	URL      string
	Checksum string
	Name     string
	Status   images.ImageStatus
}

// TODO(gthiemonge) Remove when all the clients are used in the octavia controller
func getOpenstackClient(
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

func getTags(
	imageName string,
) []string {
	if strings.HasPrefix(imageName, "octavia-amphora-vert-") {
		return []string{AmphoraImageVertTag}
	} else if strings.HasPrefix(imageName, "octavia-amphora-") {
		return []string{AmphoraImageTag}
	}
	return []string{}
}

func ensureAmphoraImage(
	imageClient *gophercloud.ServiceClient,
	log *logr.Logger,
	amphoraImage OctaviaAmphoraImage,
	imageStatus string,
) (bool, error) {
	log.Info(fmt.Sprintf("Ensuring image %+v", amphoraImage.Name))

	// Status is none, the image doesn't exist
	if imageStatus == "none" {
		visibility := images.ImageVisibilityPrivate
		imageCreateOpts := images.CreateOpts{
			Name:            amphoraImage.Name,
			Visibility:      &visibility,
			Tags:            getTags(amphoraImage.Name),
			ContainerFormat: "bare",
			DiskFormat:      "qcow2",
			Properties: map[string]string{
				// TODO(gthiemonge) hw_architecture is not set due to a bug in
				// placement/nova (OSPRH-6215)
				//"hw_architecture": "x86_64",
				"image_checksum": amphoraImage.Checksum,
			},
		}

		log.Info(fmt.Sprintf("Creating image %s", amphoraImage.Name))
		image, err := images.Create(imageClient, imageCreateOpts).Extract()
		if err != nil {
			return false, err
		}

		imageStatus = string(image.Status)
		amphoraImage.ID = image.ID
	}

	// Status is queue, image needs to be imported
	if imageStatus == string(images.ImageStatusQueued) {
		imageImportCreateOpts := imageimport.CreateOpts{
			Name: imageimport.WebDownloadMethod,
			URI:  amphoraImage.URL,
		}

		log.Info(fmt.Sprintf("Uploading image %s %s (%s)", amphoraImage.Name, amphoraImage.ID, amphoraImage.URL))
		err := imageimport.Create(imageClient, amphoraImage.ID, imageImportCreateOpts).ExtractErr()
		if err != nil {
			return false, err
		}
	}

	// Image is active, it's imported and ready
	if imageStatus == string(images.ImageStatusActive) {
		return true, nil
	}

	return false, nil
}

func amphoraImageListByTag(
	imageClient *gophercloud.ServiceClient,
	log *logr.Logger,
	tag string,
) (map[string]OctaviaAmphoraImage, error) {
	listOpts := images.ListOpts{
		Sort: "created_at:desc",
		Tags: []string{tag},
	}

	allPages, err := images.List(imageClient, listOpts).AllPages()
	if err != nil {
		return nil, err
	}

	allImages, err := images.ExtractImages(allPages)
	if err != nil {
		return nil, err
	}

	existingAmphoraImages := map[string]OctaviaAmphoraImage{}
	for _, image := range allImages {
		var checksum string
		prop := image.Properties["image_checksum"]
		if str, ok := prop.(string); ok {
			checksum = str
		} else {
			checksum = ""
		}
		if _, ok := existingAmphoraImages[image.Name]; ok {
			log.Info(fmt.Sprintf("Multiple '%s' images exist. The Octavia service uses only the most recent image", image.Name))
		} else {
			existingAmphoraImages[image.Name] = OctaviaAmphoraImage{
				ID:       image.ID,
				Name:     image.Name,
				Status:   image.Status,
				Checksum: checksum,
			}
		}
	}

	return existingAmphoraImages, nil
}

func amphoraImageList(
	imageClient *gophercloud.ServiceClient,
	log *logr.Logger,
) (map[string]OctaviaAmphoraImage, error) {
	amphoraImages, err := amphoraImageListByTag(imageClient, log, AmphoraImageTag)
	if err != nil {
		return nil, err
	}
	amphoraVertImages, err := amphoraImageListByTag(imageClient, log, AmphoraImageVertTag)
	if err != nil {
		return nil, err
	}
	for k, v := range amphoraVertImages {
		if _, ok := amphoraImages[k]; !ok {
			amphoraImages[k] = v
		}
	}
	return amphoraImages, nil
}

func EnsureAmphoraImages(
	ctx context.Context,
	instance *octaviav1.Octavia,
	log *logr.Logger,
	helper *helper.Helper,
	imageList []OctaviaAmphoraImage,
) (bool, error) {
	osclient, err := getOpenstackClient(ctx, instance, helper)
	if err != nil {
		return false, fmt.Errorf("error while getting a service client when creating images: %w", err)
	}

	imageClient, err := GetImageClient(osclient)
	if err != nil {
		return false, fmt.Errorf("error while getting an image client: %w", err)
	}

	existingAmphoraImages, err := amphoraImageList(imageClient, log)
	if err != nil {
		return false, fmt.Errorf("error while getting the list of images: %w", err)
	}

	imagesReady := true
	for _, amphoraImage := range imageList {
		var existingImageStatus string
		if existingImage, ok := existingAmphoraImages[amphoraImage.Name]; ok {
			existingImageStatus = string(existingImage.Status)
			amphoraImage.ID = existingImage.ID
		} else {
			existingImageStatus = "none"
		}
		ready, err := ensureAmphoraImage(imageClient, log, amphoraImage, existingImageStatus)
		if err != nil {
			return false, fmt.Errorf("error while uploading the amphora images: %w", err)
		}
		if !ready {
			imagesReady = false
		}
	}

	if !imagesReady {
		// One of the images is not ready
		return false, nil
	}

	return true, nil
}
