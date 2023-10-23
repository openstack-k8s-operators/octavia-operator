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
	"github.com/openstack-k8s-operators/lib-common/modules/common/condition"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// HealthManager is the role name for amphora controllers for the Octavia Health Manager services
	HealthManager = "healthmanager"
	// Housekeeping is the role name for amphora controllers for the Octavia Housekeeping services
	Housekeeping = "housekeeping"
	// Worker is the role name for amphora controllers for the Octavia Workerservices
	Worker = "worker"
)

// OctaviaAmphoraControllerSpec defines common state for all Octavia Amphora Controllers
type OctaviaAmphoraControllerSpec struct {
	// +kubebuilder:validation:Required
	// MariaDB instance name
	// Right now required by the maridb-operator to get the credentials from the instance to create the DB
	// Might not be required in future
	DatabaseInstance string `json:"databaseInstance"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=octavia
	// DatabaseUser - optional username used for octavia DB, defaults to octavia
	// TODO: -> implement needs work in mariadb-operator, right now only octavia
	DatabaseUser string `json:"databaseUser"`

	// +kubebuilder:validation:Optional
	// DatabaseHostname - Octavia DB hostname
	DatabaseHostname string `json:"databaseHostname,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=octavia
	// ServiceUser - service user name (TODO: beagles, do we need this at all)
	ServiceUser string `json:"serviceUser"`

	// +kubebuilder:validation:Required
	// ServiceAccount - service account name used internally to provide Octavia services the default SA name
	ServiceAccount string `json:"serviceAccount"`

	// +kubebuilder:validation:Optional
	// ContainerImage - Amphora Controller Container Image URL
	ContainerImage string `json:"containerImage,omitempty"`

	// +kubebuilder:validation:Required
	// Role - the role for the controller (one of worker, housekeeping, healthmanager)
	Role string `json:"role"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=1
	// +kubebuilder:validation:Maximum=32
	// +kubebuilder:validation:Minimum=0
	// Replicas - Octavia Worker Replicas
	Replicas *int32 `json:"replicas"`

	// +kubebuilder:validation:Required
	// Secret containing OpenStack password information for octavia OctaviaDatabasePassword, AdminPassword
	Secret string `json:"secret"`

	// *kubebuilder:validation:Required
	// Secret containing certs for securing communication with amphora based Load Balancers
	LoadBalancerCerts string `json:"certssecret"`

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
	// TransportURLSecret - Secret containing RabbitMQ transportURL
	TransportURLSecret string `json:"transportURLSecret,omitempty"`

	// +kubebuilder:validation:Optional
	// Resources - Compute Resources required by this service (Limits/Requests).
	// https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// +kubebuilder:validation:Optional
	// NetworkAttachments is a list of NetworkAttachment resource names to expose the services to the given network
	NetworkAttachments []string `json:"networkAttachments,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=service
	// TenantName - the name of the OpenStack tenant that controls the Octavia resources
	// TODO(gthiemonge) same as ServiceAccount?
	TenantName string `json:"tenantName"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default={manageLbMgmtNetworks: true, subnetIpVersion: 4}
	LbMgmtNetworks OctaviaLbMgmtNetworks `json:"lbMgmtNetwork"`
}

// OctaviaAmphoraControllerStatus defines the observed state of the Octavia Amphora Controller
type OctaviaAmphoraControllerStatus struct {
	// ReadyCount of Octavia Amphora Controllers
	ReadyCount int32 `json:"readyCount,omitempty"`

	// Map of hashes to track e.g. job status
	Hash map[string]string `json:"hash,omitempty"`

	// Conditions
	Conditions condition.Conditions `json:"conditions,omitempty" optional:"true"`

	// Octavia Database Hostname
	DatabaseHostname string `json:"databaseHostname,omitempty"`

	// NetworkAttachment status of the deployment pods
	NetworkAttachments map[string][]string `json:"networkAttachments,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="NetworkAttachments",type="string",JSONPath=".status.spec.networkAttachments",description="NetworkAttachments"
//+kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.conditions[0].status",description="Status"
//+kubebuilder:printcolumn:name="Message",type="string",JSONPath=".status.conditions[0].message",description="Message"

// OctaviaAmphoraController is the Schema for the octaviaworkers API
type OctaviaAmphoraController struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OctaviaAmphoraControllerSpec   `json:"spec,omitempty"`
	Status OctaviaAmphoraControllerStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// OctaviaAmphoraControllerList contains a list of OctaviaWorker
type OctaviaAmphoraControllerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OctaviaAmphoraController `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OctaviaAmphoraController{}, &OctaviaAmphoraControllerList{})
}

// IsReady - returns true if service is ready to work
func (instance OctaviaAmphoraController) IsReady() bool {
	return instance.Status.Conditions.IsTrue(condition.DeploymentReadyCondition)
}
