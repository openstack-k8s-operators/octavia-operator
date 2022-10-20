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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OctaviaWorkerSpec defines the desired state of OctaviaWorker
type OctaviaWorkerSpec struct {
	AmphoraControllerBase `json:",inline"`
}

// OctaviaWorkerStatus defines the observed state of OctaviaWorker
type OctaviaWorkerStatus struct {
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
// OctaviaWorker is the Schema for the octaviaworkers API
type OctaviaWorker struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OctaviaWorkerSpec   `json:"spec,omitempty"`
	Status OctaviaWorkerStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true
// OctaviaWorkerList contains a list of OctaviaWorker
type OctaviaWorkerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OctaviaWorker `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OctaviaWorker{}, &OctaviaWorkerList{})
}

// IsReady - returns true if service is ready to work
func (instance OctaviaWorker) IsReady() bool {
	return instance.Status.Conditions.IsTrue(condition.DeploymentReadyCondition)
}
