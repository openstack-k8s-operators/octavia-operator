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

// OctaviaRsyslogSpec defines common state for all Octavia Amphora Controllers
type OctaviaRsyslogSpec struct {
	OctaviaRsyslogSpecCore `json:",inline"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default="quay.io/podified-antelope-centos9/openstack-rsyslog:current-podified"
	// ContainerImage - Rsyslog Container Image URL
	ContainerImage string `json:"containerImage,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default="quay.io/podified-antelope-centos9/openstack-octavia-health-manager:current-podified"
	// InitContainerImage - Rsyslog init Container Image URL for
	InitContainerImage string `json:"initContainerImage,omitempty"`
}

// OctaviaRsyslogSpecCore -
type OctaviaRsyslogSpecCore struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=octavia
	// ServiceUser - service user name (TODO: beagles, do we need this at all)
	ServiceUser string `json:"serviceUser"`

	// +kubebuilder:validation:Required
	// ServiceAccount - service account name used internally to provide Octavia services the default SA name
	ServiceAccount string `json:"serviceAccount"`

	// +kubebuilder:validation:Optional
	// NodeSelector to target subset of worker nodes running this service
	NodeSelector *map[string]string `json:"nodeSelector,omitempty"`

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
	// +kubebuilder:default={"octavia"}
	// NetworkAttachments is a list of NetworkAttachment resource names to expose the services to the given network
	NetworkAttachments []string `json:"networkAttachments,omitempty"`

	// +kubebuilder:validation:Optional
	// AdminLogTargets is a list of OctaviaRsyslogTarget, the admin logs are forwarded to those targets.
	// Use only when forwarding to an external Rsyslog server.
	AdminLogTargets []OctaviaRsyslogTarget `json:"adminLogTargets,omitempty"`

	// +kubebuilder:validation:Optional
	// TenantLogTargets is a list of OctaviaRsyslogTarget, the tenant logs are forwarded to those targets.
	// Use only when forwarding to an external Rsyslog server.
	TenantLogTargets []OctaviaRsyslogTarget `json:"tenantLogTargets,omitempty"`

	// +kubebuilder:validation:Optional
	// OctaviaProviderSubnetGateway -
	OctaviaProviderSubnetGateway string `json:"octaviaProviderSubnetGateway"`

	// +kubebuilder:validation:Optional
	// OctaviaProviderSubnetCIDR -
	OctaviaProviderSubnetCIDR string `json:"octaviaProviderSubnetCIDR"`

	// +kubebuilder:validation:Optional
	// +listType:=atomic
	// OctaviaProviderSubnetExtraCIDRs -
	OctaviaProviderSubnetExtraCIDRs []string `json:"octaviaProviderSubnetExtraCIDRs,omitempty"`
}

// OctaviaRsyslogStatus defines the observed state of the Octavia Amphora Controller
type OctaviaRsyslogStatus struct {
	// ReadyCount of Octavia Amphora Controllers
	ReadyCount int32 `json:"readyCount,omitempty"`

	// DesiredNumberScheduled - total number of the nodes which should be running Daemon
	DesiredNumberScheduled int32 `json:"desiredNumberScheduled,omitempty"`

	// Map of hashes to track e.g. job status
	Hash map[string]string `json:"hash,omitempty"`

	// Conditions
	Conditions condition.Conditions `json:"conditions,omitempty" optional:"true"`

	// NetworkAttachment status of the deployment pods
	NetworkAttachments map[string][]string `json:"networkAttachments,omitempty"`

	// ObservedGeneration - the most recent generation observed for this
	// service. If the observed generation is less than the spec generation,
	// then the controller has not processed the latest changes injected by
	// the opentack-operator in the top-level CR (e.g. the ContainerImage)
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="NetworkAttachments",type="string",JSONPath=".status.networkAttachments",description="NetworkAttachments"
//+kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.conditions[0].status",description="Status"
//+kubebuilder:printcolumn:name="Message",type="string",JSONPath=".status.conditions[0].message",description="Message"

// OctaviaRsyslog is the Schema for the octaviaworkers API
type OctaviaRsyslog struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OctaviaRsyslogSpec   `json:"spec,omitempty"`
	Status OctaviaRsyslogStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// OctaviaRsyslogList contains a list of OctaviaWorker
type OctaviaRsyslogList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OctaviaRsyslog `json:"items"`
}

type OctaviaRsyslogTarget struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

func init() {
	SchemeBuilder.Register(&OctaviaRsyslog{}, &OctaviaRsyslogList{})
}

// IsReady - returns true if service is ready to work
func (instance OctaviaRsyslog) IsReady() bool {
	return instance.Status.Conditions.IsTrue(condition.DeploymentReadyCondition) &&
		instance.Status.Conditions.IsTrue(condition.NetworkAttachmentsReadyCondition)
}
