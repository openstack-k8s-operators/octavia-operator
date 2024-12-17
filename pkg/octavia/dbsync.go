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
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"

	"github.com/openstack-k8s-operators/lib-common/modules/common/env"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

const (
	// InitContainerCommand -
	InitContainerCommand = "/usr/local/bin/container-scripts/init.sh"
)

// DbSyncJob func
func DbSyncJob(
	instance *octaviav1.Octavia,
	labels map[string]string,
	annotations map[string]string,
) *batchv1.Job {
	volumeMounts := GetVolumeMounts("db-sync")
	volumes := GetVolumes(instance.Name)

	envVars := map[string]env.Setter{}
	envVars["KOLLA_CONFIG_STRATEGY"] = env.SetValue("COPY_ALWAYS")

	// add CA cert if defined
	if instance.Spec.OctaviaAPI.TLS.CaBundleSecretName != "" {
		volumes = append(volumes, instance.Spec.OctaviaAPI.TLS.CreateVolume())
		volumeMounts = append(volumeMounts, instance.Spec.OctaviaAPI.TLS.CreateVolumeMounts(nil)...)
	}

	args := []string{
		"-c",
		InitContainerCommand,
	}

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name + "-db-sync",
			Namespace: instance.Namespace,
			Labels:    labels,
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: annotations,
				},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						FSGroup: ptr.To(OctaviaUID),
					},
					RestartPolicy:                corev1.RestartPolicyOnFailure,
					ServiceAccountName:           instance.RbacResourceName(),
					AutomountServiceAccountToken: ptr.To(false),
					Containers: []corev1.Container{
						{
							Name:            ServiceName + "-db-sync",
							Image:           instance.Spec.OctaviaAPI.ContainerImage,
							SecurityContext: GetOctaviaSecurityContext(),
							Env:             env.MergeEnvs([]corev1.EnvVar{}, envVars),
							VolumeMounts:    volumeMounts,
						},
					},
					InitContainers: []corev1.Container{
						{
							Name:            "init",
							Image:           instance.Spec.OctaviaAPI.ContainerImage,
							SecurityContext: GetOctaviaSecurityContext(),
							Command: []string{
								"/bin/bash",
							},
							Args:         args,
							VolumeMounts: GetInitVolumeMounts(),
						},
					},
					Volumes: volumes,
				},
			},
		},
	}

	if instance.Spec.NodeSelector != nil {
		job.Spec.Template.Spec.NodeSelector = *instance.Spec.NodeSelector
	}

	return job
}
