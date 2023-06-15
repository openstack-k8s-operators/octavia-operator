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
	"fmt"

	"github.com/openstack-k8s-operators/lib-common/modules/common/condition"
	"github.com/openstack-k8s-operators/lib-common/modules/common/endpoint"
	"github.com/openstack-k8s-operators/lib-common/modules/common/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// Container image fall-back defaults

	// OctaviaAPIContainerImage is the fall-back container image for OctaviaAPI
	OctaviaAPIContainerImage = "quay.io/podified-antelope-centos9/openstack-octavia-api:current-podified"
)

// OctaviaSpec defines the desired state of Octavia
type OctaviaSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

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
	// +kubebuilder:default=octavia
	// ServiceUser - service user name
	ServiceUser string `json:"serviceUser"`

	// +kubebuilder:validation:Required
	// Secret containing OpenStack password information for octavia OctaviaDatabasePassword, AdminPassword
	Secret string `json:"secret"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default={database: OctaviaDatabasePassword, service: OctaviaPassword}
	// PasswordSelectors - Selectors to identify the DB and ServiceUser password from the Secret
	PasswordSelectors PasswordSelector `json:"passwordSelectors,omitempty"`

	// +kubebuilder:validation:Optional
	// NodeSelector to target subset of worker nodes running this service
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// +kubebuilder:validation:Optional
	// Debug - enable debug for different deploy stages. If an init container is used, it runs and the
	// actual action pod gets started with sleep infinity
	Debug OctaviaAPIDebug `json:"debug,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	// PreserveJobs - do not delete jobs after they finished e.g. to check logs
	PreserveJobs bool `json:"preserveJobs,omitempty"`

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

	// +kubebuilder:validation:Required
	// OctaviaAPI - Spec definition for the API service of the Octavia deployment
	OctaviaAPI OctaviaAPISpec `json:"octaviaAPI"`
}

// PasswordSelector to identify the DB and AdminUser password from the Secret
type PasswordSelector struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:default="OctaviaDatabasePassword"
	// Database - Selector to get the octavia Database user password from the Secret
	// TODO: not used, need change in mariadb-operator
	Database string `json:"database,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:default="OctaviaPassword"
	// Service - Selector to get the service user password from the Secret
	Service string `json:"service,omitempty"`
}

// OctaviaStatus defines the observed state of Octavia
type OctaviaStatus struct {

	// Map of hashes to track e.g. job status
	Hash map[string]string `json:"hash,omitempty"`

	// API endpoint
	APIEndpoints map[string]string `json:"apiEndpoints,omitempty"`

	// Conditions
	Conditions condition.Conditions `json:"conditions,omitempty" optional:"true"`

	// Octavia Database Hostname
	DatabaseHostname string `json:"databaseHostname,omitempty"`

	// ServiceID - the ID of the registered service in keystone
	ServiceID string `json:"serviceID,omitempty"`

	// ReadyCount of octavia API instances
	OctaviaAPIReadyCount int32 `json:"apireadyCount,omitempty"`

	// ReadyCount of octavia Worker instances
	OctaviaWorkerReadyCount int32 `json:"workerreadyCount,omitempty"`

	// ReadyCount of octavia Housekeeping instances
	OctaviaHousekeepingReadyCount int32 `json:"housekeepingreadyCount,omitempty"`

	// ReadyCount of octavia HealthManager instances
	OctaviaHealthManagerReadyCount int32 `json:"healthmanagerreadyCount,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.conditions[0].status",description="Status"
//+kubebuilder:printcolumn:name="Message",type="string",JSONPath=".status.conditions[0].message",description="Message"

// Octavia is the Schema for the octavia API
type Octavia struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OctaviaSpec   `json:"spec,omitempty"`
	Status OctaviaStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// OctaviaList contains a list of Octavia
type OctaviaList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Octavia `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Octavia{}, &OctaviaList{})
}

// GetEndpoint - returns OpenStack endpoint url for type
func (instance Octavia) GetEndpoint(endpointType endpoint.Endpoint) (string, error) {
	if url, found := instance.Status.APIEndpoints[string(endpointType)]; found {
		return url, nil
	}
	return "", fmt.Errorf("%s endpoint not found", string(endpointType))
}

// IsReady - returns true if service is ready to server requests
func (instance Octavia) IsReady() bool {
	ready := instance.Status.OctaviaAPIReadyCount > 0
	// TODO: add other ready counts
	return ready
}

// SetupDefaults - initializes any CRD field defaults based on environment variables (the defaulting mechanism itself is implemented via webhooks)
func SetupDefaults() {
	// Acquire environmental defaults and initialize Octavia defaults with them
	octaviaDefaults := OctaviaDefaults{
		ContainerImageURL: util.GetEnvVar("OCTAVIA_API_IMAGE_URL_DEFAULT", OctaviaAPIContainerImage),
	}

	SetupOctaviaDefaults(octaviaDefaults)
}


// RbacConditionsSet - set the conditions for the rbac object
func (instance Octavia) RbacConditionsSet(c *condition.Condition) {
	instance.Status.Conditions.Set(c)
}

// RbacNamespace - return the namespace
func (instance Octavia) RbacNamespace() string {
	return instance.Namespace
}

// RbacResourceName - return the name to be used for rbac objects (serviceaccount, role, rolebinding)
func (instance Octavia) RbacResourceName() string {
	return "octavia-" + instance.Name
}
