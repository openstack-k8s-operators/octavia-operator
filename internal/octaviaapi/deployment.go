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

// Package octaviaapi contains functionality for managing Octavia API deployments
package octaviaapi

import (
	"fmt"

	topologyv1 "github.com/openstack-k8s-operators/infra-operator/apis/topology/v1beta1"
	"github.com/openstack-k8s-operators/lib-common/modules/common"
	"github.com/openstack-k8s-operators/lib-common/modules/common/affinity"
	"github.com/openstack-k8s-operators/lib-common/modules/common/env"
	"github.com/openstack-k8s-operators/lib-common/modules/common/service"
	"github.com/openstack-k8s-operators/lib-common/modules/common/tls"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/octavia-operator/internal/octavia"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

const (
	// ServiceCommand -
	ServiceCommand = "/usr/local/bin/kolla_start"

	// InitContainerCommand -
	InitContainerCommand = "/usr/local/bin/container-scripts/init.sh"
)

// Deployment func
func Deployment(
	instance *octaviav1.OctaviaAPI,
	configHash string,
	labels map[string]string,
	annotations map[string]string,
	topology *topologyv1.Topology,
) (*appsv1.Deployment, error) {

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

	args := []string{"-c", ServiceCommand}
	//
	// https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/
	//
	livenessProbe.HTTPGet = &corev1.HTTPGetAction{
		Path: "/healthcheck",
		Port: intstr.IntOrString{Type: intstr.Int, IntVal: int32(octavia.OctaviaPublicPort)},
	}
	readinessProbe.HTTPGet = &corev1.HTTPGetAction{
		Path: "/healthcheck",
		Port: intstr.IntOrString{Type: intstr.Int, IntVal: int32(octavia.OctaviaPublicPort)},
	}

	if instance.Spec.TLS.API.Enabled(service.EndpointPublic) {
		livenessProbe.HTTPGet.Scheme = corev1.URISchemeHTTPS
		readinessProbe.HTTPGet.Scheme = corev1.URISchemeHTTPS
	}

	// create Volume and VolumeMounts
	volumes := getVolumes(instance.Name)
	volumeMounts := getVolumeMounts("octavia-api")
	volumeMountsDriverAgent := getVolumeMounts("octavia-driver-agent")

	// add CA cert if defined
	if instance.Spec.TLS.CaBundleSecretName != "" {
		volumes = append(volumes, instance.Spec.TLS.CreateVolume())
		volumeMounts = append(volumeMounts, instance.Spec.TLS.CreateVolumeMounts(nil)...)
		volumeMountsDriverAgent = append(volumeMountsDriverAgent, instance.Spec.TLS.CreateVolumeMounts(nil)...)

	}

	for _, endpt := range []service.Endpoint{service.EndpointInternal, service.EndpointPublic} {
		if instance.Spec.TLS.API.Enabled(endpt) {
			var tlsEndptCfg tls.GenericService
			switch endpt {
			case service.EndpointPublic:
				tlsEndptCfg = instance.Spec.TLS.API.Public
			case service.EndpointInternal:
				tlsEndptCfg = instance.Spec.TLS.API.Internal
			}

			svc, err := tlsEndptCfg.ToService()
			if err != nil {
				return nil, err
			}
			volumes = append(volumes, svc.CreateVolume(endpt.String()))
			volumeMounts = append(volumeMounts, svc.CreateVolumeMounts(endpt.String())...)
			volumeMountsDriverAgent = append(volumeMountsDriverAgent, svc.CreateVolumeMounts(endpt.String())...)
		}
	}

	if instance.Spec.TLS.Ovn.Enabled() {
		svc := tls.Service{
			SecretName: *instance.Spec.TLS.Ovn.SecretName,
			CaMount:    ptr.To("/var/lib/config-data/tls/certs/ovndbca.crt"),
		}
		volumes = append(volumes, svc.CreateVolume("ovndb"))
		volumeMounts = append(volumeMounts, svc.CreateVolumeMounts("ovndb")...)
		volumeMountsDriverAgent = append(volumeMountsDriverAgent, svc.CreateVolumeMounts("ovndb")...)
	}

	envVars := map[string]env.Setter{}
	envVars["KOLLA_CONFIG_STRATEGY"] = env.SetValue("COPY_ALWAYS")
	envVars["CONFIG_HASH"] = env.SetValue(configHash)

	// TODO: reduce code duplication.
	agentEnvVars := map[string]env.Setter{}
	agentEnvVars["KOLLA_CONFIG_STRATEGY"] = env.SetValue("COPY_ALWAYS")
	agentEnvVars["CONFIG_HASH"] = env.SetValue(configHash)

	serviceName := fmt.Sprintf("%s-api", octavia.ServiceName)

	initArgs := []string{
		"-c",
		InitContainerCommand,
	}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: instance.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Replicas: instance.Spec.Replicas,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: annotations,
					Labels:      labels,
				},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						FSGroup: ptr.To(octavia.OctaviaUID),
					},
					ServiceAccountName:           instance.Spec.ServiceAccount,
					AutomountServiceAccountToken: ptr.To(false),
					Containers: []corev1.Container{
						{
							Name: serviceName,
							Command: []string{
								"/bin/bash",
							},
							Args:            args,
							Image:           instance.Spec.ContainerImage,
							SecurityContext: octavia.GetOctaviaSecurityContext(),
							Env:             env.MergeEnvs([]corev1.EnvVar{}, envVars),
							VolumeMounts:    volumeMounts,
							Resources:       instance.Spec.Resources,
							ReadinessProbe:  readinessProbe,
							LivenessProbe:   livenessProbe,
						},
						{
							Name:            fmt.Sprintf("%s-provider-agent", serviceName),
							Image:           instance.Spec.ContainerImage,
							SecurityContext: octavia.GetOctaviaSecurityContext(),
							Env:             env.MergeEnvs([]corev1.EnvVar{}, agentEnvVars),
							VolumeMounts:    volumeMountsDriverAgent,
							Resources:       instance.Spec.Resources,
							ReadinessProbe:  readinessProbe,
							LivenessProbe:   livenessProbe,
						},
					},
					InitContainers: []corev1.Container{
						{
							Name:            "init",
							Image:           instance.Spec.ContainerImage,
							SecurityContext: octavia.GetOctaviaSecurityContext(),
							Command: []string{
								"/bin/bash",
							},
							Args:         initArgs,
							VolumeMounts: octavia.GetInitVolumeMounts(),
						},
					},
					Volumes: volumes,
				},
			},
		},
	}
	if instance.Spec.NodeSelector != nil {
		deployment.Spec.Template.Spec.NodeSelector = *instance.Spec.NodeSelector
	}
	if topology != nil {
		topology.ApplyTo(&deployment.Spec.Template)
	} else {
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
	}

	return deployment, nil
}
