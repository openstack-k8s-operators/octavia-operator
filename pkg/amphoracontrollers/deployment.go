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
	"fmt"
	"github.com/openstack-k8s-operators/lib-common/modules/common"
	"github.com/openstack-k8s-operators/lib-common/modules/common/affinity"
	"github.com/openstack-k8s-operators/lib-common/modules/common/env"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/octavia-operator/pkg/octavia"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AmphoraControllerDeployment is the common deployment code for services that act as amphora
// controllers.
func AmphoraControllerDeployment(
	instance *metav1.ObjectMeta,
	spec *octaviav1.AmphoraControllerBaseSpec,
	configHash string,
	octaviaService string,
	labels map[string]string,
) *appsv1.Deployment {

	// TODO(beagles): is this correct? Do we want to use the same UID as director?
	runAsUser := int64(0)

	// TODO(beagles): Using the same params for the liveness and
	// readiness probes for all octavia amphorae controller services
	// is probably okay for now. Hardcoding? Maybe not so much.
	livenessProbe := &corev1.Probe{
		TimeoutSeconds:      15,
		PeriodSeconds:       13,
		InitialDelaySeconds: 3,
	}
	readinessProbe := &corev1.Probe{
		TimeoutSeconds:      15,
		PeriodSeconds:       15,
		InitialDelaySeconds: 5,
	}

	// XXX TODO(beagles): this isn't valid AT ALL, but putting in place until I can sort out a more
	// reasonable option.
	livenessProbe.Exec = &corev1.ExecAction{
		Command: []string{
			"/bin/true",
		},
	}

	readinessProbe.Exec = &corev1.ExecAction{
		Command: []string{
			"/bin/true",
		},
	}

	// TODO(beagles): the liveness and readiness probes are probably going to be
	// core.v1.probe.exec objects so we need to figure out what those will actually be.

	const kollaConfigFmt = "/var/lib/config-data/merged/octavia-%s-config.json"
	envVars := map[string]env.Setter{}
	envVars["KOLLA_CONFIG_FILE"] = env.SetValue(fmt.Sprintf(kollaConfigFmt, octaviaService))
	envVars["KOLLA_CONFIG_STRATEGY"] = env.SetValue("COPY_ALWAYS")
	envVars["CONFIG_HASH"] = env.SetValue(configHash)
	serviceName := fmt.Sprintf("%s-%s", octavia.ServiceName, octaviaService)
	args := []string{"-c", "/usr/local/bin/kolla_set_configs && /usr/local/bin/kolla_start"}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: instance.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Replicas: &spec.Replicas,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: octavia.ServiceAccount,
					Containers: []corev1.Container{
						{
							Name: serviceName,
							Command: []string{
								"/bin/bash",
							},
							Args:  args,
							Image: spec.ContainerImage,
							SecurityContext: &corev1.SecurityContext{
								RunAsUser: &runAsUser,
							},
							Env:            env.MergeEnvs([]corev1.EnvVar{}, envVars),
							VolumeMounts:   octavia.GetVolumeMounts(),
							Resources:      spec.Resources,
							ReadinessProbe: readinessProbe,
							LivenessProbe:  livenessProbe,
						},
					},
					Volumes: octavia.GetVolumes(instance.Name),
				},
			},
		},
	}
	// If possible two pods of the same service should not
	// run on the same worker node. If this is not possible
	// the get still created on the same worker node.
	deployment.Spec.Template.Spec.Affinity = affinity.DistributePods(
		common.AppSelector,
		[]string{
			serviceName,
		},
		corev1.LabelHostname,
	)
	if spec.NodeSelector != nil && len(spec.NodeSelector) > 0 {
		deployment.Spec.Template.Spec.NodeSelector = spec.NodeSelector
	}

	return deployment
}
