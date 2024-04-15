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
	"github.com/openstack-k8s-operators/lib-common/modules/common/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// Container image fall-back defaults

	// OctaviaAPIContainerImage is the fall-back container image for OctaviaAPI
	OctaviaAPIContainerImage = "quay.io/podified-antelope-centos9/openstack-octavia-api:current-podified"

	// OctaviaHousekeepingContainerImage is the fall-back container image for OctaviaHousekeeping
	OctaviaHousekeepingContainerImage = "quay.io/podified-antelope-centos9/openstack-octavia-housekeeping:current-podified"

	// OctaviaHealthManagerContainerImage is the fall-back container image for OctaviaHealthManager
	OctaviaHealthManagerContainerImage = "quay.io/podified-antelope-centos9/openstack-octavia-health-manager:current-podified"

	// OctaviaWorkerContainerImage is the fall-back container image for OctaviaWorker
	OctaviaWorkerContainerImage = "quay.io/podified-antelope-centos9/openstack-octavia-worker:current-podified"

	// ApacheImage - default fall-back image for Apache
	ApacheContainerImage = "registry.redhat.io/ubi9/httpd-24:latest"
)

// OctaviaSpec defines the desired state of Octavia
type OctaviaSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	OctaviaSpecBase `json:",inline"`

	// +kubebuilder:validation:Required
	// OctaviaAPI - Spec definition for the API service of the Octavia deployment
	OctaviaAPI OctaviaAPISpec `json:"octaviaAPI"`

	// +kubebuilder:validation:Optional
	// OctaviaHousekeeping - Spec definition for the Octavia Housekeeping agent for the Octavia deployment
	OctaviaHousekeeping OctaviaAmphoraControllerSpec `json:"octaviaHousekeeping"`

	// +kubebuilder:validation:Optional
	// OctaviaHousekeeping - Spec definition for the Octavia Housekeeping agent for the Octavia deployment
	OctaviaHealthManager OctaviaAmphoraControllerSpec `json:"octaviaHealthManager"`

	// +kubebuilder:validation:Optional
	// OctaviaHousekeeping - Spec definition for the Octavia Housekeeping agent for the Octavia deployment
	OctaviaWorker OctaviaAmphoraControllerSpec `json:"octaviaWorker"`
}

// OctaviaSpecCore - this version has no containerImages and is used by OpenStackControlplane
type OctaviaSpecCore struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	OctaviaSpecBase `json:",inline"`

	// +kubebuilder:validation:Required
	// OctaviaAPI - Spec definition for the API service of the Octavia deployment
	OctaviaAPI OctaviaAPISpecCore `json:"octaviaAPI"`

	// +kubebuilder:validation:Optional
	// OctaviaHousekeeping - Spec definition for the Octavia Housekeeping agent for the Octavia deployment
	OctaviaHousekeeping OctaviaAmphoraControllerSpecCore `json:"octaviaHousekeeping"`

	// +kubebuilder:validation:Optional
	// OctaviaHousekeeping - Spec definition for the Octavia Housekeeping agent for the Octavia deployment
	OctaviaHealthManager OctaviaAmphoraControllerSpecCore `json:"octaviaHealthManager"`

	// +kubebuilder:validation:Optional
	// OctaviaHousekeeping - Spec definition for the Octavia Housekeeping agent for the Octavia deployment
	OctaviaWorker OctaviaAmphoraControllerSpecCore `json:"octaviaWorker"`
}

// OctaviaSpecBase -
type OctaviaSpecBase struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// +kubebuilder:validation:Required
	// MariaDB instance name
	// Right now required by the maridb-operator to get the credentials from the instance to create the DB
	// Might not be required in future
	DatabaseInstance string `json:"databaseInstance"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=octavia
	// DatabaseAccount - name of MariaDBAccount which will be used to connect
	// for the main octavia database
	DatabaseAccount string `json:"databaseAccount"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=octavia-persistence
	// PersistenceDatabaseAccount - name of MariaDBAccount which will be used
	// to connect for the persistence database
	PersistenceDatabaseAccount string `json:"persistenceDatabaseAccount"`

	// +kubebuilder:validation:Required
	// +kubebuilder:default=rabbitmq
	// RabbitMQ instance name
	// Needed to request a transportURL that is created and used in Octavia
	RabbitMqClusterName string `json:"rabbitMqClusterName"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=octavia
	// ServiceUser - service user name
	ServiceUser string `json:"serviceUser"`

	// +kubebuilder:validation:Required
	// Secret containing OpenStack password information for octavia's keystone
	// password; no longer used for database password
	Secret string `json:"secret"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default={service: OctaviaPassword}
	// PasswordSelectors - Selectors to identify the DB and ServiceUser password from the Secret
	PasswordSelectors PasswordSelector `json:"passwordSelectors,omitempty"`

	// +kubebuilder:validation:Optional
	// NodeSelector to target subset of worker nodes running this service
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

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

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=service
	// TenantName - the name of the OpenStack tenant that controls the Octavia resources
	TenantName string `json:"tenantName"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default={manageLbMgmtNetworks: true, subnetIpVersion: 4}
	LbMgmtNetworks OctaviaLbMgmtNetworks `json:"lbMgmtNetwork"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=octavia-ssh-pubkey
	// LoadBalancerSSHPubKey - The name of the ConfigMap containing the
	// pubilc key for connecting to the amphorae via SSH
	LoadBalancerSSHPubKey string `json:"sshPubkey,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=octavia-ssh-privkey-secret
	// LoadBalancerSSHPrivKey - The name of the secret that will be used to
	// store the private key for connecting to amphorae via SSH
	LoadBalancerSSHPrivKey string `json:"sshPrivkeySecret,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default={}
	// AmphoraCustomFlavors - User-defined flavors for Octavia
	AmphoraCustomFlavors []OctaviaAmphoraFlavor `json:"amphoraCustomFlavors,omitempty"`

	// +kubebuilder:validation:Optional
	// Resources - Compute Resources required by this service (Limits/Requests).
	// https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// +kubebuilder:validation:Optional
	// Octavia Container Image URL
	AmphoraImageContainerImage string `json:"amphoraImageContainerImage"`

	// +kubebuilder:validation:Required
	// Apache Container Image URL
	ApacheContainerImage string `json:"apacheContainerImage"`
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

// OctaviaLbMgmtNetworks Settings for Octavia management networks
type OctaviaLbMgmtNetworks struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=true
	ManageLbMgmtNetworks bool `json:"manageLbMgmtNetworks,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=4
	// IP Version of the managed subnets
	SubnetIPVersion int `json:"subnetIpVersion,omitempty"`
}

// OctaviaAmphoraFlavor Settings for custom Amphora flavors
type OctaviaAmphoraFlavor struct {
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// +kubebuilder:validation:Optional
	Description string `json:"description"`

	// +kubebuilder:validation:Required
	VCPUs int `json:"VCPUs"`

	// +kubebuilder:validation:Required
	RAM int `json:"RAM"`

	// +kubebuilder:validation:Required
	Disk int `json:"disk"`

	// +kubebuilder:validation:Optional
	RxTxFactor string `json:"RxTxFactor"`
}

// OctaviaStatus defines the observed state of Octavia
type OctaviaStatus struct {

	// Map of hashes to track e.g. job status
	Hash map[string]string `json:"hash,omitempty"`

	// Conditions
	Conditions condition.Conditions `json:"conditions,omitempty" optional:"true"`

	// Octavia Database Hostname
	DatabaseHostname string `json:"databaseHostname,omitempty"`

	// TransportURLSecret - Secret containing RabbitMQ transportURL
	TransportURLSecret string `json:"transportURLSecret,omitempty"`

	// ReadyCount of octavia API instances
	OctaviaAPIReadyCount int32 `json:"apireadyCount,omitempty"`

	// ReadyCount of octavia Worker instances
	OctaviaWorkerReadyCount int32 `json:"workerreadyCount,omitempty"`

	// ReadyCount of octavia Housekeeping instances
	OctaviaHousekeepingReadyCount int32 `json:"housekeepingreadyCount,omitempty"`

	// ReadyCount of octavia HealthManager instances
	OctaviaHealthManagerReadyCount int32 `json:"healthmanagerreadyCount,omitempty"`

	// ObservedGeneration - the most recent generation observed for this
	// service. If the observed generation is less than the spec generation,
	// then the controller has not processed the latest changes injected by
	// the opentack-operator in the top-level CR (e.g. the ContainerImage)
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:path=octavias
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
		APIContainerImageURL:           util.GetEnvVar("RELATED_IMAGE_OCTAVIA_API_IMAGE_URL_DEFAULT", OctaviaAPIContainerImage),
		HousekeepingContainerImageURL:  util.GetEnvVar("RELATED_IMAGE_OCTAVIA_HOUSEKEEPING_IMAGE_URL_DEFAULT", OctaviaHousekeepingContainerImage),
		HealthManagerContainerImageURL: util.GetEnvVar("RELATED_IMAGE_OCTAVIA_HEALTHMANAGER_IMAGE_URL_DEFAULT", OctaviaHealthManagerContainerImage),
		WorkerContainerImageURL:        util.GetEnvVar("RELATED_IMAGE_OCTAVIA_WORKER_IMAGE_URL_DEFAULT", OctaviaWorkerContainerImage),
		ApacheContainerImageURL:        util.GetEnvVar("RELATED_IMAGE_OCTAVIA_APACHE_IMAGE_URL_DEFAULT", ApacheContainerImage),
		// No default for AmphoraImageContainerImageURL
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
