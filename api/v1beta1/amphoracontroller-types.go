/*
Copyright 2022.

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

package v1beta1

import (

	"github.com/openstakc-k8s-operators/lib-common/modules/common/condition"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AmphoraControllerBase defines common state for all Octavia Amphora Controllers
type AmphoraControllerBase struct {
	// +kubebuilder:validation:Required
	// MariaDB instance name
	// Right now required by the maridb-operator to get the credentials from the instance to create the DB
	// Might not be required in future
	DatabaseInstance string `json:"databaseInstance,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=octavia
	// DatabaseUser - optional username used for octavia DB, defaults to octavia
	// TODO: -> implement needs work in mariadb-operator, right now only octavia
	DatabaseUser string `json:"databaseUser"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=octavia
	// ServiceUser - service user name (TODO: beagles, do we need this at all)
	ServiceUser string `json:"serviceUser"`

	// +kubebuilder:validation:Optional
	// ContainerImage - Amphora Controller Container Image URL
	ContainerImage string `json:"containerImage,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=1
	// +kubebuilder:validation:Maximum=32
	// +kubebuilder:validation:Minimum=0
	// Replicas - Octavia Worker Replicas
	Replicas int32 `json:"replicas"`

	// +kubebuilder:validation:Required
	// Secret containing OpenStack password information for octavia OctaviaDatabasePassword, AdminPassword
	Secret string `json:"secret"`

	// *kubebuilder:validation:Required
	// Secret containing certs for securing communication with amphora based Load Balancers
	LoadBalancerCerts string `json:"secret"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default={database: OctaviaDatabasePassword, service: OctaviaPassword}
	// PasswordSelectors - Selectors to identify the DB and AdminUser password from the Secret
	PasswordSelectors PasswordSelector `json:"passwordSelectors,omitempty"`

	// +kubebuilder:validation:Optional
	// NodeSelector to target subset of worker nodes running this service
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default="# add your customization here"
	// CustomServiceConfig - customize the service config using this parameter to change service defaults,
	// or overwrite rendered information using raw OpenStack config format. The content gets added to
	// to /etc/<service>/<service>.conf.d directory as custom.conf file.
	CustomServiceConfig string `json:"customServiceConfig,omitempty"`

	// +kubebuilder:validation:Optional
	// ConfigOverwrite - interface to overwrite default config files like e.g. logging.conf or policy.json.
	// But can also be used to add additional files. Those get added to the service config dir in /etc/<service> .
	// TODO: -> implement
	DefaultConfigOverwrite map[string]string `json:"defaultConfigOverwrite,omitempty"`

	// +kubebuilder:validation:Optional
	// Resources - Compute Resources required by this service (Limits/Requests).
	// https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// +kubebuilder:validation:Optional
	// Debug - enable debug for service deployment
	Debug bool `json:"debug,omitempty"`
}

// AmphoraControllerStatus defines the observed state of the Octavia Amphora Controller
type AmphoraControllerStatus struct {
	// ReadyCount of Octavia Amphora Controllers
	ReadyCount int32 `json:"readyCount,omitempty"`

	// Conditions
	Conditions condition.Conditions `json:"conditions,omitempty" optional:"true"`

	// Octavia Database Hostname
	DatabaseHostname string `json:"databaseHostname,omitempty"`
}
