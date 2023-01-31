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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OctaviaHousekeepingSpec defines the desired state of OctaviaHousekeeping
type OctaviaHousekeepingSpec struct {
	AmphoraControllerBaseSpec `json:",inline"`
}

// OctaviaHousekeepingStatus defines the observed state of OctaviaHousekeeping
type OctaviaHousekeepingStatus struct {
	// ReadyCount of octavia API instances
	ReadyCount int32 `json:"readyCount,omitempty"`

	// Map of hashes to track e.g. job status
	Hash map[string]string `json:"hash,omitempty"`

	// Conditions
	Conditions condition.Conditions `json:"conditions,omitempty" optional:"true"`
}

// OctaviaHousekeeping is the Schema for the octaviaworkers API
//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.conditions[0].status",description="Status"
//+kubebuilder:printcolumn:name="Message",type="string",JSONPath=".status.conditions[0].message",description="Message"
type OctaviaHousekeeping struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OctaviaHousekeepingSpec   `json:"spec,omitempty"`
	Status OctaviaHousekeepingStatus `json:"status,omitempty"`
}

// OctaviaHousekeepingList contains a list of OctaviaHousekeeping
//+kubebuilder:object:root=true
type OctaviaHousekeepingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OctaviaHousekeeping `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OctaviaHousekeeping{}, &OctaviaHousekeepingList{})
}

// IsReady - returns true if service is ready to work
func (instance OctaviaHousekeeping) IsReady() bool {
	return instance.Status.Conditions.IsTrue(condition.DeploymentReadyCondition)
}
