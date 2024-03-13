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
	"github.com/openstack-k8s-operators/lib-common/modules/common/env"

	corev1 "k8s.io/api/core/v1"
)

// APIDetails information
type APIDetails struct {
	ContainerImage          string
	DatabaseHost            string
	DatabaseName            string
	PersistenceDatabaseName string
	TransportURLSecret      string
	OSPSecret               string
	UserPasswordSelector    string
	VolumeMounts            []corev1.VolumeMount
}

const (
	// InitContainerCommand -
	InitContainerCommand = "/usr/local/bin/container-scripts/init.sh"
)

// InitContainer - init container for octavia api pods
func InitContainer(init APIDetails) []corev1.Container {
	runAsUser := int64(0)

	args := []string{
		"-c",
		InitContainerCommand,
	}

	envVars := map[string]env.Setter{}
	envVars["DatabaseHost"] = env.SetValue(init.DatabaseHost)
	envVars["DatabaseName"] = env.SetValue(init.DatabaseName)

	envs := []corev1.EnvVar{
		{
			Name: "AdminPassword",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: init.OSPSecret,
					},
					Key: init.UserPasswordSelector,
				},
			},
		},
	}

	// TODO(beagles): should this be conditional? It seems like it should be required.
	if init.TransportURLSecret != "" {
		envs = append(envs,
			corev1.EnvVar{
				Name: "TransportURL",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: init.TransportURLSecret,
						},
						Key: "transport_url",
					},
				},
			},
		)
	}
	envs = env.MergeEnvs(envs, envVars)

	return []corev1.Container{
		{
			Name:  "init",
			Image: init.ContainerImage,
			SecurityContext: &corev1.SecurityContext{
				RunAsUser: &runAsUser,
			},
			Command: []string{
				"/bin/bash",
			},
			Args:         args,
			Env:          envs,
			VolumeMounts: GetInitVolumeMounts(),
		},
	}
}
