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
	"fmt"

	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ImageUploadDetails struct {
	ContainerImage string
	VolumeMounts   []corev1.VolumeMount
}

const (
	// ServiceCommand -
	ServiceCommand = "cp -f /usr/local/apache2/conf/httpd.conf /etc/httpd/conf/httpd.conf && /usr/bin/run-httpd"
)

func getVolumes(name string) []corev1.Volume {
	return []corev1.Volume{
		{
			Name: "amphora-image",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		{
			Name: "httpd-config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-config-data", name),
					},
				},
			},
		},
	}
}

func getInitVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		{
			Name:      "amphora-image",
			MountPath: "/usr/local/apache2/htdocs",
		},
	}
}

// GetVolumeMounts - general VolumeMounts
func getVolumeMounts(serviceName string) []corev1.VolumeMount {
	return []corev1.VolumeMount{
		{
			Name:      "amphora-image",
			MountPath: "/usr/local/apache2/htdocs",
		},
		{
			Name:      "httpd-config",
			MountPath: "/usr/local/apache2/conf/httpd.conf",
			SubPath:   "httpd.conf",
			ReadOnly:  true,
		},
	}
}

// Deployment func
func ImageUploadDeployment(
	instance *octaviav1.Octavia,
	labels map[string]string,
	annotations map[string]string,
) *appsv1.Deployment {
	initVolumeMounts := getInitVolumeMounts()

	// TODO(gthiemonge) healthchecks?
	args := []string{"-c", ServiceCommand}

	serviceName := fmt.Sprintf("%s-image-upload", ServiceName)

	depl := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: instance.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: annotations,
					Labels:      labels,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: instance.RbacResourceName(),
					// TODO(gthiemonge) Expose service on Pod
					HostNetwork: true,
					Containers: []corev1.Container{
						{
							Name: "octavia-amphora-httpd",
							Command: []string{
								"/bin/bash",
							},
							Args:         args,
							Image:        instance.Spec.ApacheContainerImage,
							VolumeMounts: getVolumeMounts("octavia-image-upload"),
							Resources:    instance.Spec.Resources,
							// TODO(gthiemonge) Probes?
						},
						//{
						//	Name: serviceName,
						//	Command: []string{
						//		"/bin/bash",
						//	},
						//	Image: instance.Spec.AmphoraImageContainerImage,
						//	SecurityContext: &corev1.SecurityContext{
						//		RunAsUser: &runAsUser,
						//	},
						//	VolumeMounts: getVolumeMounts("octavia-image-upload"),
						//},
					},
					Volumes: getVolumes(instance.Name),
				},
			},
		},
	}

	initContainerDetails := ImageUploadDetails{
		ContainerImage: instance.Spec.AmphoraImageContainerImage,
		VolumeMounts:   initVolumeMounts,
	}
	depl.Spec.Template.Spec.InitContainers = initContainer(initContainerDetails)

	return depl
}

func initContainer(init ImageUploadDetails) []corev1.Container {
	runAsUser := int64(0)
	envs := []corev1.EnvVar{
		{
			Name:  "DEST_DIR",
			Value: "/usr/local/apache2/htdocs",
		},
	}

	return []corev1.Container{
		{
			Name:  "init",
			Image: init.ContainerImage,
			SecurityContext: &corev1.SecurityContext{
				RunAsUser: &runAsUser,
			},
			Env:          envs,
			VolumeMounts: getInitVolumeMounts(),
		},
	}
}
