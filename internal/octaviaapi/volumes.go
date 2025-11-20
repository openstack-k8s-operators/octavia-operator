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

package octaviaapi

import (
	"github.com/openstack-k8s-operators/octavia-operator/internal/octavia"
	corev1 "k8s.io/api/core/v1"
)

// getVolumes - service volumes
func getVolumes(name string) []corev1.Volume {

	volumes := []corev1.Volume{
		{
			Name: "octavia-run",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{Medium: ""},
			},
		},
	}

	return append(octavia.GetVolumes(name), volumes...)
}

// getVolumeMounts - general VolumeMounts
func getVolumeMounts(serviceName string) []corev1.VolumeMount {

	// The API pod has an extra volume so the API and the provider agent can
	// communicate with each other.
	volumeMounts := []corev1.VolumeMount{
		{
			Name:      "octavia-run",
			MountPath: "/run/octavia",
			ReadOnly:  false,
		},
	}
	return append(octavia.GetVolumeMounts(serviceName), volumeMounts...)
}
