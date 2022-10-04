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

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// OctaviaWorkerSpec defines the desired state of OctaviaWorker
type OctaviaWorkerSpec struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=octavia
	// ServiceUser - optional username used for this service to register in cinder
	ServiceUser string `json:"serviceUser"`

	// +kubebuilder:validation:Optional
	// ContainerImage - Octavia Worker Container Image URL
	ContainerImage string `json:"containerImage,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=1
	// Replicas - Octavia Worker Replicas
	Replicas int32 `json:"replicas"`

	// +kubebuilder:validation:Optional
	// NodeSelector to target subset of worker nodes running this service
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
}

// OctaviaWorkerStatus defines the observed state of OctaviaWorker
type OctaviaWorkerStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

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
