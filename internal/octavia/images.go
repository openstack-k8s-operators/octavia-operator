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
	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/imageimport"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
)

const (
	// AmphoraImageTag is the tag used for Octavia amphora images
	AmphoraImageTag = "amphora-image"
	// AmphoraImageVertTag is the tag used for Octavia amphora vertical images
	AmphoraImageVertTag = "amphora-image-vert"
)

// AmphoraImage represents an Octavia amphora image with its metadata
type AmphoraImage struct {
	ID       string
	URL      string
	Checksum string
	Name     string
	Status   images.ImageStatus
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
	ctx context.Context,
	imageClient *gophercloud.ServiceClient,
	log *logr.Logger,
	amphoraImage AmphoraImage,
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
		image, err := images.Create(ctx, imageClient, imageCreateOpts).Extract()
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
		err := imageimport.Create(ctx, imageClient, amphoraImage.ID, imageImportCreateOpts).ExtractErr()
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
	ctx context.Context,
	imageClient *gophercloud.ServiceClient,
	log *logr.Logger,
	tag string,
) (map[string]AmphoraImage, error) {
	listOpts := images.ListOpts{
		Sort: "created_at:desc",
		Tags: []string{tag},
	}

	allPages, err := images.List(imageClient, listOpts).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	allImages, err := images.ExtractImages(allPages)
	if err != nil {
		return nil, err
	}

	existingAmphoraImages := map[string]AmphoraImage{}
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
			existingAmphoraImages[image.Name] = AmphoraImage{
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
	ctx context.Context,
	imageClient *gophercloud.ServiceClient,
	log *logr.Logger,
) (map[string]AmphoraImage, error) {
	amphoraImages, err := amphoraImageListByTag(ctx, imageClient, log, AmphoraImageTag)
	if err != nil {
		return nil, err
	}
	amphoraVertImages, err := amphoraImageListByTag(ctx, imageClient, log, AmphoraImageVertTag)
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

// EnsureAmphoraImages ensures that required Octavia amphora images are available in OpenStack
func EnsureAmphoraImages(
	ctx context.Context,
	instance *octaviav1.Octavia,
	log *logr.Logger,
	helper *helper.Helper,
	imageList []AmphoraImage,
) (bool, error) {
	osclient, err := GetOpenstackServiceClient(ctx, instance, helper)
	if err != nil {
		return false, fmt.Errorf("error while getting a service client when creating images: %w", err)
	}

	imageClient, err := GetImageClient(osclient)
	if err != nil {
		return false, fmt.Errorf("error while getting an image client: %w", err)
	}

	existingAmphoraImages, err := amphoraImageList(ctx, imageClient, log)
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
		ready, err := ensureAmphoraImage(ctx, imageClient, log, amphoraImage, existingImageStatus)
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

// GetImageOwnerID retrieves the owner ID for images in the OpenStack service
func GetImageOwnerID(
	ctx context.Context,
	instance *octaviav1.Octavia,
	helper *helper.Helper,
) (string, error) {
	osclient, err := GetOpenstackServiceClient(ctx, instance, helper)
	if err != nil {
		return "", fmt.Errorf("error while getting a service client when getting image owner: %w", err)
	}

	project, err := GetProject(ctx, osclient, instance.Spec.TenantName)
	if err != nil {
		return "", fmt.Errorf("error while getting the project %s: %w", instance.Spec.TenantName, err)
	}

	return project.ID, nil
}
