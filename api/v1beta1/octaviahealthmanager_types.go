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

// OctaviaHealthManagerSpec defines the desired state of OctaviaHealthManager
type OctaviaHealthManagerSpec struct {
	AmphoraControllerBaseSpec `json:",inline"`
}

// OctaviaHealthManagerStatus defines the observed state of OctaviaHealthManager
type OctaviaHealthManagerStatus struct {
	// ReadyCount of octavia API instances
	ReadyCount int32 `json:"readyCount,omitempty"`

	// Map of hashes to track e.g. job status
	Hash map[string]string `json:"hash,omitempty"`

	// Conditions
	Conditions condition.Conditions `json:"conditions,omitempty" optional:"true"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.conditions[0].status",description="Status"
//+kubebuilder:printcolumn:name="Message",type="string",JSONPath=".status.conditions[0].message",description="Message"
// OctaviaHealthManager is the Schema for the octaviaworkers API
type OctaviaHealthManager struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OctaviaHealthManagerSpec   `json:"spec,omitempty"`
	Status OctaviaHealthManagerStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true
// OctaviaHealthManagerList contains a list of OctaviaHealthManager
type OctaviaHealthManagerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OctaviaHealthManager `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OctaviaHealthManager{}, &OctaviaHealthManagerList{})
}

// IsReady - returns true if service is ready to work
func (instance OctaviaHealthManager) IsReady() bool {
	return instance.Status.Conditions.IsTrue(condition.DeploymentReadyCondition)
}
