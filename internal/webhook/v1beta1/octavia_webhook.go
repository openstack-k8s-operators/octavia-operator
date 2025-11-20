/*
Copyright 2025.

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

// Package v1beta1 contains webhook implementations for Octavia resources.
package v1beta1

import (
	"context"
	"errors"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	octaviav1beta1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
)

var (
	// ErrUnexpectedObjectType is returned when an unexpected object type is received.
	ErrUnexpectedObjectType = errors.New("expected an Octavia object but got unexpected type")
	// ErrUnexpectedNewObjectType is returned when an unexpected new object type is received during update.
	ErrUnexpectedNewObjectType = errors.New("expected an Octavia object for the newObj but got unexpected type")
)

// nolint:unused
// log is for logging in this package.
var octavialog = logf.Log.WithName("octavia-resource")

// SetupOctaviaWebhookWithManager registers the webhook for Octavia in the manager.
func SetupOctaviaWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&octaviav1beta1.Octavia{}).
		WithValidator(&OctaviaCustomValidator{}).
		WithDefaulter(&OctaviaCustomDefaulter{}).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// +kubebuilder:webhook:path=/mutate-octavia-openstack-org-v1beta1-octavia,mutating=true,failurePolicy=fail,sideEffects=None,groups=octavia.openstack.org,resources=octavias,verbs=create;update,versions=v1beta1,name=moctavia-v1beta1.kb.io,admissionReviewVersions=v1

// OctaviaCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind Octavia when those are created or updated.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as it is used only for temporary operations and does not need to be deeply copied.
type OctaviaCustomDefaulter struct {
	// TODO(user): Add more fields as needed for defaulting
}

var _ webhook.CustomDefaulter = &OctaviaCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind Octavia.
func (d *OctaviaCustomDefaulter) Default(_ context.Context, obj runtime.Object) error {
	octavia, ok := obj.(*octaviav1beta1.Octavia)

	if !ok {
		return fmt.Errorf("%w: %T", ErrUnexpectedObjectType, obj)
	}
	octavialog.Info("Defaulting for Octavia", "name", octavia.GetName())

	// Call the defaulting logic from the API package
	octavia.Default()

	return nil
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-octavia-openstack-org-v1beta1-octavia,mutating=false,failurePolicy=fail,sideEffects=None,groups=octavia.openstack.org,resources=octavias,verbs=create;update,versions=v1beta1,name=voctavia-v1beta1.kb.io,admissionReviewVersions=v1

// OctaviaCustomValidator struct is responsible for validating the Octavia resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type OctaviaCustomValidator struct {
	// TODO(user): Add more fields as needed for validation
}

var _ webhook.CustomValidator = &OctaviaCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type Octavia.
func (v *OctaviaCustomValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	octavia, ok := obj.(*octaviav1beta1.Octavia)
	if !ok {
		return nil, fmt.Errorf("%w: %T", ErrUnexpectedObjectType, obj)
	}
	octavialog.Info("Validation for Octavia upon creation", "name", octavia.GetName())

	// Call the validation logic from the API package
	return octavia.ValidateCreate()
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type Octavia.
func (v *OctaviaCustomValidator) ValidateUpdate(_ context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	octavia, ok := newObj.(*octaviav1beta1.Octavia)
	if !ok {
		return nil, fmt.Errorf("%w: %T", ErrUnexpectedNewObjectType, newObj)
	}
	octavialog.Info("Validation for Octavia upon update", "name", octavia.GetName())

	// Call the validation logic from the API package
	return octavia.ValidateUpdate(oldObj)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type Octavia.
func (v *OctaviaCustomValidator) ValidateDelete(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	octavia, ok := obj.(*octaviav1beta1.Octavia)
	if !ok {
		return nil, fmt.Errorf("%w: %T", ErrUnexpectedObjectType, obj)
	}
	octavialog.Info("Validation for Octavia upon deletion", "name", octavia.GetName())

	// Call the validation logic from the API package
	return octavia.ValidateDelete()
}
