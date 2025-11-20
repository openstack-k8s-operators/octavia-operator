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
	corev1 "k8s.io/api/core/v1"

	"github.com/openstack-k8s-operators/octavia-operator/internal/octavia"
)

const (
	configVolume = "amphora-certs"
)

var (
	// Files get mounted as root:root, but process is running as octavia
	configMode int32 = 0644
)

// GetVolumes returns the volumes required for amphora controller pods
func GetVolumes(name string) []corev1.Volume {
	var config0640AccessMode int32 = 0640
	return append(
		octavia.GetVolumes(name),
		corev1.Volume{
			Name: "hm-ports",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: octavia.HmConfigMap,
					},
					DefaultMode: &config0640AccessMode,
				},
			},
		},
	)
}

// GetInitVolumeMounts returns the volume mounts for init containers in amphora controller pods
func GetInitVolumeMounts() []corev1.VolumeMount {
	return append(
		octavia.GetInitVolumeMounts(),
		corev1.VolumeMount{
			Name:      "hm-ports",
			MountPath: "/var/lib/hmports",
			ReadOnly:  true,
		},
	)
}

// GetCertVolume - service volumes
func GetCertVolume(certSecretName string) []corev1.Volume {
	return []corev1.Volume{
		{
			Name: configVolume,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					DefaultMode: &configMode,
					SecretName:  certSecretName,
				},
			},
		},
	}
}

// GetCertVolumeMount - certificate VolumeMount
func GetCertVolumeMount() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		{
			Name:      configVolume,
			MountPath: "/etc/octavia/certs",
			ReadOnly:  true,
		},
	}
}
