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
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// OctaviaDefaults -
type OctaviaDefaults struct {
	APIContainerImageURL           string
	HousekeepingContainerImageURL  string
	HealthManagerContainerImageURL string
	WorkerContainerImageURL        string
}

var octaviaDefaults OctaviaDefaults

// log is for logging in this package.
var octavialog = logf.Log.WithName("octavia-resource")

// SetupOctaviaDefaults - initialize Octavia spec defaults for use with either internal or external webhooks
func SetupOctaviaDefaults(defaults OctaviaDefaults) {
	octaviaDefaults = defaults
	octavialog.Info("Octavia defaults initialized", "defaults", defaults)
}

// SetupWebhookWithManager sets up the webhook with the Manager
func (r *Octavia) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

//+kubebuilder:webhook:path=/mutate-octavia-openstack-org-v1beta1-octavia,mutating=true,failurePolicy=fail,sideEffects=None,groups=octavia.openstack.org,resources=octavias,verbs=create;update,versions=v1beta1,name=moctavia.kb.io,admissionReviewVersions=v1

var _ webhook.Defaulter = &Octavia{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *Octavia) Default() {
	octavialog.Info("default", "name", r.Name)

	r.Spec.Default()
}

// Default - set defaults for this Octavia spec
func (spec *OctaviaSpec) Default() {
	if spec.OctaviaAPI.ContainerImage == "" {
		spec.OctaviaAPI.ContainerImage = octaviaDefaults.APIContainerImageURL
	}
	if spec.OctaviaHousekeeping.ContainerImage == "" {
		spec.OctaviaHousekeeping.ContainerImage = octaviaDefaults.HousekeepingContainerImageURL
	}
	if spec.OctaviaHealthManager.ContainerImage == "" {
		spec.OctaviaHealthManager.ContainerImage = octaviaDefaults.HealthManagerContainerImageURL
	}
	if spec.OctaviaWorker.ContainerImage == "" {
		spec.OctaviaWorker.ContainerImage = octaviaDefaults.WorkerContainerImageURL
	}
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
//+kubebuilder:webhook:path=/validate-octavia-openstack-org-v1beta1-octavia,mutating=false,failurePolicy=fail,sideEffects=None,groups=octavia.openstack.org,resources=octavias,verbs=create;update,versions=v1beta1,name=voctavia.kb.io,admissionReviewVersions=v1

var _ webhook.Validator = &Octavia{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *Octavia) ValidateCreate() (admission.Warnings, error) {
	octavialog.Info("validate create", "name", r.Name)

	// TODO(user): fill in your validation logic upon object creation.
	return nil, nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *Octavia) ValidateUpdate(old runtime.Object) (admission.Warnings, error) {
	octavialog.Info("validate update", "name", r.Name)

	// TODO(user): fill in your validation logic upon object update.
	return nil, nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *Octavia) ValidateDelete() (admission.Warnings, error) {
	octavialog.Info("validate delete", "name", r.Name)

	// TODO(user): fill in your validation logic upon object deletion.
	return nil, nil
}
