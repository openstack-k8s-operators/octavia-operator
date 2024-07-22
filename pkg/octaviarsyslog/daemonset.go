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

package octaviarsyslog

import (
	"github.com/openstack-k8s-operators/lib-common/modules/common"
	"github.com/openstack-k8s-operators/lib-common/modules/common/affinity"
	"github.com/openstack-k8s-operators/lib-common/modules/common/env"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/octavia-operator/pkg/octavia"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DaemonSet func
func DaemonSet(
	instance *octaviav1.OctaviaRsyslog,
	configHash string,
	labels map[string]string,
	annotations map[string]string,
) *appsv1.DaemonSet {
	runAsUser := int64(0)
	serviceName := "octavia-rsyslog"

	// The API pod has an extra volume so the API and the provider agent can
	// communicate with each other.
	volumes := GetVolumes(instance.Name)
	//parentOctaviaName := octavia.GetOwningOctaviaControllerName(instance)
	//certsSecretName := fmt.Sprintf("%s-certs-secret", parentOctaviaName)
	//volumes = append(volumes, GetCertVolume(certsSecretName)...)

	volumeMounts := octavia.GetVolumeMounts(serviceName)
	//volumeMounts = append(volumeMounts, GetCertVolumeMount()...)

	livenessProbe := &corev1.Probe{
		// TODO might need tuning
		TimeoutSeconds:      15,
		PeriodSeconds:       13,
		InitialDelaySeconds: 3,
	}
	readinessProbe := &corev1.Probe{
		// TODO might need tuning
		TimeoutSeconds:      15,
		PeriodSeconds:       15,
		InitialDelaySeconds: 5,
	}

	// TODO(beagles): use equivalent's of healthcheck's in tripleo which
	// seem to largely based on connections to database. The pgrep's
	// could be tightened up too but they seem to be a bit tricky.

	livenessProbe.Exec = &corev1.ExecAction{
		Command: []string{
			"/usr/bin/pgrep", "-r", "DRST", "rsyslog",
		},
	}

	readinessProbe.Exec = &corev1.ExecAction{
		Command: []string{
			"/usr/bin/pgrep", "-r", "DRST", "rsyslog",
		},
	}

	envVars := map[string]env.Setter{}

	envVars["KOLLA_CONFIG_STRATEGY"] = env.SetValue("COPY_ALWAYS")
	envVars["CONFIG_HASH"] = env.SetValue(configHash)
	envVars["NODE_NAME"] = env.DownwardAPI("spec.nodeName")

	daemonset := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: instance.Namespace,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: annotations,
					Labels:      labels,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: instance.Spec.ServiceAccount,
					Containers: []corev1.Container{
						{
							Name:           serviceName,
							Image:          instance.Spec.ContainerImage,
							Env:            env.MergeEnvs([]corev1.EnvVar{}, envVars),
							VolumeMounts:   volumeMounts,
							Resources:      instance.Spec.Resources,
							ReadinessProbe: readinessProbe,
							LivenessProbe:  livenessProbe,
							SecurityContext: &corev1.SecurityContext{
								RunAsUser: &runAsUser,
							},
						},
					},
					Volumes: volumes,
				},
			},
		},
	}
	// If possible two pods of the same service should not
	// run on the same worker node. If this is not possible
	// the get still created on the same worker node.
	daemonset.Spec.Template.Spec.Affinity = affinity.DistributePods(
		common.AppSelector,
		[]string{
			serviceName,
		},
		corev1.LabelHostname,
	)
	if instance.Spec.NodeSelector != nil && len(instance.Spec.NodeSelector) > 0 {
		daemonset.Spec.Template.Spec.NodeSelector = instance.Spec.NodeSelector
	}

	initContainerDetails := APIDetails{
		// TODO(gthiemonge) Using Octavia HM Container image is a workaround to get a container with pyroute2
		// Replace it by an init container image with pyroute2 when it's available
		// OSPRH-8434
		ContainerImage: octaviav1.OctaviaHealthManagerContainerImage,
		VolumeMounts:   octavia.GetInitVolumeMounts(),
		Env:            env.MergeEnvs([]corev1.EnvVar{}, envVars),
	}
	daemonset.Spec.Template.Spec.InitContainers = InitContainer(initContainerDetails)

	return daemonset
}
