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
	"k8s.io/utils/ptr"
)

// ImageUploadDetails contains the configuration details for image upload operations
type ImageUploadDetails struct {
	ContainerImage string
	VolumeMounts   []corev1.VolumeMount
}

const (
	// ServiceCommand -
	ServiceCommand = "cp -f /usr/local/apache2/conf/httpd.conf /etc/httpd/conf/httpd.conf && /usr/bin/run-httpd"
)

func getVolumes(name string) []corev1.Volume {
	var config0640AccessMode int32 = 0640

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
				Secret: &corev1.SecretVolumeSource{
					DefaultMode: &config0640AccessMode,
					SecretName:  name + "-config-data",
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
func getVolumeMounts() []corev1.VolumeMount {
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

// ImageUploadDeployment creates a deployment for uploading Octavia amphora images
func ImageUploadDeployment(
	instance *octaviav1.Octavia,
	labels map[string]string,
) *appsv1.Deployment {
	initVolumeMounts := getInitVolumeMounts()

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
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName:           instance.RbacResourceName(),
					AutomountServiceAccountToken: ptr.To(false),
					Containers: []corev1.Container{
						{
							Name: "octavia-amphora-httpd",
							Command: []string{
								"/bin/bash",
							},
							Args:         args,
							Image:        instance.Spec.ApacheContainerImage,
							VolumeMounts: getVolumeMounts(),
							Resources:    instance.Spec.Resources,
							// TODO(gthiemonge) do we need probes?
						},
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

	if instance.Spec.NodeSelector != nil {
		depl.Spec.Template.Spec.NodeSelector = *instance.Spec.NodeSelector
	}

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
