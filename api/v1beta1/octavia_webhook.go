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

	"github.com/openstack-k8s-operators/lib-common/modules/common/service"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
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
	ApacheContainerImageURL        string
}

var octaviaDefaults OctaviaDefaults

// log is for logging in this package.
var octavialog = logf.Log.WithName("octavia-resource")

// SetupOctaviaDefaults - initialize Octavia spec defaults for use with either internal or external webhooks
func SetupOctaviaDefaults(defaults OctaviaDefaults) {
	octaviaDefaults = defaults
	octavialog.V(1).Info("Octavia defaults initialized", "defaults", defaults)
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
	octavialog.V(1).Info("default", "name", r.Name)

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
	if spec.ApacheContainerImage == "" {
		spec.ApacheContainerImage = octaviaDefaults.ApacheContainerImageURL
	}
}

// Default - set defaults for this Octavia core spec (this version is used by the OpenStackControlplane webhook)
func (spec *OctaviaSpecCore) Default() {
	// nothing here yet
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
//+kubebuilder:webhook:path=/validate-octavia-openstack-org-v1beta1-octavia,mutating=false,failurePolicy=fail,sideEffects=None,groups=octavia.openstack.org,resources=octavias,verbs=create;update,versions=v1beta1,name=voctavia.kb.io,admissionReviewVersions=v1

var _ webhook.Validator = &Octavia{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *Octavia) ValidateCreate() (admission.Warnings, error) {
	octavialog.V(1).Info("validate create", "name", r.Name)

	var allErrs field.ErrorList
	basePath := field.NewPath("spec")
	if err := r.Spec.ValidateCreate(basePath); err != nil {
		allErrs = append(allErrs, err...)
	}

	if len(allErrs) != 0 {
		return nil, apierrors.NewInvalid(
			schema.GroupKind{Group: "octavia.openstack.org", Kind: "Octavia"},
			r.Name, allErrs)
	}

	return nil, nil
}

// ValidateCreate - Exported function wrapping non-exported validate functions,
// this function can be called externally to validate an octavia spec.
func (r *OctaviaSpec) ValidateCreate(basePath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	// validate the service override key is valid
	allErrs = append(allErrs, service.ValidateRoutedOverrides(
		basePath.Child("octaviaAPI").Child("override").Child("service"),
		r.OctaviaAPI.Override.Service)...)

	return allErrs
}

func (r *OctaviaSpecCore) ValidateCreate(basePath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	// validate the service override key is valid
	allErrs = append(allErrs, service.ValidateRoutedOverrides(
		basePath.Child("octaviaAPI").Child("override").Child("service"),
		r.OctaviaAPI.Override.Service)...)

	return allErrs
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *Octavia) ValidateUpdate(old runtime.Object) (admission.Warnings, error) {
	octavialog.V(1).Info("validate update", "name", r.Name)

	oldOctavia, ok := old.(*Octavia)
	if !ok || oldOctavia == nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("unable to convert existing object"))
	}

	var allErrs field.ErrorList
	basePath := field.NewPath("spec")

	if err := r.Spec.ValidateUpdate(oldOctavia.Spec, basePath); err != nil {
		allErrs = append(allErrs, err...)
	}

	if len(allErrs) != 0 {
		return nil, apierrors.NewInvalid(
			schema.GroupKind{Group: "octavia.openstack.org", Kind: "Octavia"},
			r.Name, allErrs)
	}

	return nil, nil
}

// ValidateUpdate - Exported function wrapping non-exported validate functions,
// this function can be called externally to validate an barbican spec.
func (r *OctaviaSpec) ValidateUpdate(old OctaviaSpec, basePath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	// validate the service override key is valid
	allErrs = append(allErrs, service.ValidateRoutedOverrides(
		basePath.Child("octaviaAPI").Child("override").Child("service"),
		r.OctaviaAPI.Override.Service)...)

	return allErrs
}

func (r *OctaviaSpecCore) ValidateUpdate(old OctaviaSpecCore, basePath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	// validate the service override key is valid
	allErrs = append(allErrs, service.ValidateRoutedOverrides(
		basePath.Child("octaviaAPI").Child("override").Child("service"),
		r.OctaviaAPI.Override.Service)...)

	return allErrs
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *Octavia) ValidateDelete() (admission.Warnings, error) {
	octavialog.Info("validate delete", "name", r.Name)

	// TODO(user): fill in your validation logic upon object deletion.
	return nil, nil
}
