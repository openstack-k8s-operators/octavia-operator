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

	topologyv1 "github.com/openstack-k8s-operators/infra-operator/apis/topology/v1beta1"
	"github.com/openstack-k8s-operators/lib-common/modules/common/service"
	common_webhook "github.com/openstack-k8s-operators/lib-common/modules/common/webhook"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
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
	OctaviaAPIRouteTimeout         int
	RsyslogContainerImageURL       string
}

var octaviaDefaults OctaviaDefaults

// log is for logging in this package.
var octavialog = logf.Log.WithName("octavia-resource")

// SetupOctaviaDefaults - initialize Octavia spec defaults for use with either internal or external webhooks
func SetupOctaviaDefaults(defaults OctaviaDefaults) {
	octaviaDefaults = defaults
	octavialog.Info("Octavia defaults initialized", "defaults", defaults)
}

var _ webhook.Defaulter = &Octavia{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *Octavia) Default() {
	octavialog.Info("default", "name", r.Name)

	r.Spec.Default()
}

// Default - set defaults for this Octavia spec
func (spec *OctaviaSpec) Default() {
	// Default MessagingBus.Cluster if not set
	// Migration from deprecated fields is handled by openstack-operator
	if spec.MessagingBus.Cluster == "" {
		spec.MessagingBus.Cluster = "rabbitmq"
	}

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
	if spec.OctaviaRsyslog.ContainerImage == "" {
		spec.OctaviaRsyslog.ContainerImage = octaviaDefaults.RsyslogContainerImageURL
	}
	if spec.OctaviaRsyslog.InitContainerImage == "" {
		// TODO(gthiemonge) Using Octavia HM Container image is a workaround to get a container with pyroute2
		// Replace it by an init container image with pyroute2 when it's available
		// OSPRH-8434
		spec.OctaviaRsyslog.InitContainerImage = octaviaDefaults.HealthManagerContainerImageURL
	}
}

// Default - set defaults for this Octavia core spec (this version is used by the OpenStackControlplane webhook)
func (spec *OctaviaSpecCore) Default() {
	// Default MessagingBus.Cluster if not set
	// Migration from deprecated fields is handled by openstack-operator
	if spec.MessagingBus.Cluster == "" {
		spec.MessagingBus.Cluster = "rabbitmq"
	}
}

var _ webhook.Validator = &Octavia{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *Octavia) ValidateCreate() (admission.Warnings, error) {
	octavialog.Info("validate create", "name", r.Name)

	var allWarns []string
	var allErrs field.ErrorList
	basePath := field.NewPath("spec")

	warns, errs := r.Spec.ValidateCreate(basePath, r.Namespace)
	allWarns = append(allWarns, warns...)
	allErrs = append(allErrs, errs...)

	if len(allErrs) != 0 {
		return allWarns, apierrors.NewInvalid(
			schema.GroupKind{Group: "octavia.openstack.org", Kind: "Octavia"},
			r.Name, allErrs)
	}

	return allWarns, nil
}

// ValidateCreate - Exported function wrapping non-exported validate functions,
// this function can be called externally to validate an octavia spec.
func (r *OctaviaSpec) ValidateCreate(basePath *field.Path, namespace string) ([]string, field.ErrorList) {
	var allErrs field.ErrorList
	var allWarnings []string

	// Validate deprecated fields using centralized validation
	warnings, errs := r.OctaviaSpecBase.validateDeprecatedFieldsCreate(basePath)
	allWarnings = append(allWarnings, warnings...)
	allErrs = append(allErrs, errs...)

	// validate the service override key is valid
	allErrs = append(allErrs, service.ValidateRoutedOverrides(
		basePath.Child("octaviaAPI").Child("override").Child("service"),
		r.OctaviaAPI.Override.Service)...)

	allErrs = append(allErrs, r.ValidateOctaviaTopology(basePath, namespace)...)

	return allWarnings, allErrs
}

func (r *OctaviaSpecCore) ValidateCreate(basePath *field.Path, namespace string) ([]string, field.ErrorList) {
	var allErrs field.ErrorList
	var allWarnings []string

	// Validate deprecated fields using centralized validation
	warnings, errs := r.OctaviaSpecBase.validateDeprecatedFieldsCreate(basePath)
	allWarnings = append(allWarnings, warnings...)
	allErrs = append(allErrs, errs...)

	// validate the service override key is valid
	allErrs = append(allErrs, service.ValidateRoutedOverrides(
		basePath.Child("octaviaAPI").Child("override").Child("service"),
		r.OctaviaAPI.Override.Service)...)

	allErrs = append(allErrs, r.ValidateOctaviaTopology(basePath, namespace)...)

	return allWarnings, allErrs
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *Octavia) ValidateUpdate(old runtime.Object) (admission.Warnings, error) {
	octavialog.Info("validate update", "name", r.Name)

	oldOctavia, ok := old.(*Octavia)
	if !ok || oldOctavia == nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("unable to convert existing object"))
	}

	var allWarns []string
	var allErrs field.ErrorList
	basePath := field.NewPath("spec")

	warns, errs := r.Spec.ValidateUpdate(oldOctavia.Spec, basePath, r.Namespace)
	allWarns = append(allWarns, warns...)
	allErrs = append(allErrs, errs...)

	if len(allErrs) != 0 {
		return allWarns, apierrors.NewInvalid(
			schema.GroupKind{Group: "octavia.openstack.org", Kind: "Octavia"},
			r.Name, allErrs)
	}

	return allWarns, nil
}

// getDeprecatedFields returns the centralized list of deprecated fields for OctaviaSpecBase
func (spec *OctaviaSpecBase) getDeprecatedFields(old *OctaviaSpecBase) []common_webhook.DeprecatedFieldUpdate {
	deprecatedFields := []common_webhook.DeprecatedFieldUpdate{
		{
			DeprecatedFieldName: "rabbitMqClusterName",
			NewFieldPath:        []string{"messagingBus", "cluster"},
			NewDeprecatedValue:  &spec.RabbitMqClusterName,
			NewValue:            &spec.MessagingBus.Cluster,
		},
	}

	// If old spec is provided (UPDATE operation), add old values
	if old != nil {
		deprecatedFields[0].OldDeprecatedValue = &old.RabbitMqClusterName
	}

	return deprecatedFields
}

// validateDeprecatedFieldsCreate validates deprecated fields during CREATE operations
func (spec *OctaviaSpecBase) validateDeprecatedFieldsCreate(basePath *field.Path) ([]string, field.ErrorList) {
	// Get deprecated fields list (without old values for CREATE)
	deprecatedFieldsUpdate := spec.getDeprecatedFields(nil)

	// Convert to DeprecatedField list for CREATE validation
	deprecatedFields := make([]common_webhook.DeprecatedField, len(deprecatedFieldsUpdate))
	for i, df := range deprecatedFieldsUpdate {
		deprecatedFields[i] = common_webhook.DeprecatedField{
			DeprecatedFieldName: df.DeprecatedFieldName,
			NewFieldPath:        df.NewFieldPath,
			DeprecatedValue:     df.NewDeprecatedValue,
			NewValue:            df.NewValue,
		}
	}

	return common_webhook.ValidateDeprecatedFieldsCreate(deprecatedFields, basePath), nil
}

// validateDeprecatedFieldsUpdate validates deprecated fields during UPDATE operations
func (spec *OctaviaSpecBase) validateDeprecatedFieldsUpdate(old OctaviaSpecBase, basePath *field.Path) ([]string, field.ErrorList) {
	// Get deprecated fields list with old values
	deprecatedFields := spec.getDeprecatedFields(&old)
	return common_webhook.ValidateDeprecatedFieldsUpdate(deprecatedFields, basePath)
}

// ValidateUpdate - Exported function wrapping non-exported validate functions,
// this function can be called externally to validate an barbican spec.
func (r *OctaviaSpec) ValidateUpdate(old OctaviaSpec, basePath *field.Path, namespace string) ([]string, field.ErrorList) {
	var allErrs field.ErrorList
	var allWarnings []string

	// Validate deprecated fields using reflection-based validation
	warnings, errs := r.OctaviaSpecBase.validateDeprecatedFieldsUpdate(old.OctaviaSpecBase, basePath)
	allWarnings = append(allWarnings, warnings...)
	allErrs = append(allErrs, errs...)

	// validate the service override key is valid
	allErrs = append(allErrs, service.ValidateRoutedOverrides(
		basePath.Child("octaviaAPI").Child("override").Child("service"),
		r.OctaviaAPI.Override.Service)...)

	allErrs = append(allErrs, r.ValidateOctaviaTopology(basePath, namespace)...)

	return allWarnings, allErrs
}

func (r *OctaviaSpecCore) ValidateUpdate(old OctaviaSpecCore, basePath *field.Path, namespace string) ([]string, field.ErrorList) {
	var allErrs field.ErrorList
	var allWarnings []string

	// Validate deprecated fields using reflection-based validation
	warnings, errs := r.OctaviaSpecBase.validateDeprecatedFieldsUpdate(old.OctaviaSpecBase, basePath)
	allWarnings = append(allWarnings, warnings...)
	allErrs = append(allErrs, errs...)

	// validate the service override key is valid
	allErrs = append(allErrs, service.ValidateRoutedOverrides(
		basePath.Child("octaviaAPI").Child("override").Child("service"),
		r.OctaviaAPI.Override.Service)...)

	allErrs = append(allErrs, r.ValidateOctaviaTopology(basePath, namespace)...)

	return allWarnings, allErrs
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *Octavia) ValidateDelete() (admission.Warnings, error) {
	octavialog.Info("validate delete", "name", r.Name)

	// TODO(user): fill in your validation logic upon object deletion.
	return nil, nil
}

func (spec *OctaviaSpecCore) GetDefaultRouteAnnotations() (annotations map[string]string) {
	return map[string]string{
		"haproxy.router.openshift.io/timeout": fmt.Sprintf("%ds", octaviaDefaults.OctaviaAPIRouteTimeout),
	}
}

// SetDefaultRouteAnnotations sets HAProxy timeout values of the route
func (spec *OctaviaSpecCore) SetDefaultRouteAnnotations(annotations map[string]string) {
	const haProxyAnno = "haproxy.router.openshift.io/timeout"
	// Use a custom annotation to flag when the operator has set the default HAProxy timeout
	// With the annotation func determines when to overwrite existing HAProxy timeout with the APITimeout
	const octaviaAnno = "api.octavia.openstack.org/timeout"

	valOctavia, okOctavia := annotations[octaviaAnno]
	valHAProxy, okHAProxy := annotations[haProxyAnno]

	// Human operator set the HAProxy timeout manually
	if !okOctavia && okHAProxy {
		return
	}

	// Human operator modified the HAProxy timeout manually without removing the Octavia flag
	if okOctavia && okHAProxy && valOctavia != valHAProxy {
		delete(annotations, octaviaAnno)
		return
	}

	timeout := fmt.Sprintf("%ds", spec.APITimeout)
	annotations[octaviaAnno] = timeout
	annotations[haProxyAnno] = timeout
}

// ValidateOctaviaTopology - Returns an ErrorList if the Topology is referenced
// on a different namespace
func (spec *OctaviaSpecCore) ValidateOctaviaTopology(basePath *field.Path, namespace string) field.ErrorList {
	var allErrs field.ErrorList

	// When a TopologyRef CR is referenced, fail if a different Namespace is
	// referenced because is not supported
	allErrs = append(allErrs, topologyv1.ValidateTopologyRef(
		spec.TopologyRef, *basePath.Child("topologyRef"), namespace)...)

	// When a TopologyRef CR is referenced with an override to OctaviaAPI, fail
	// if a different Namespace is referenced because not supported
	apiPath := basePath.Child("octaviaAPI")
	allErrs = append(allErrs, spec.OctaviaAPI.ValidateTopology(apiPath, namespace)...)

	// When a TopologyRef CR is referenced with an override to OctaviaHousekeeping,
	// fail if a different Namespace is referenced because not supported
	hkPath := basePath.Child("OctaviaHousekeeping")
	allErrs = append(allErrs, spec.OctaviaHousekeeping.ValidateTopology(hkPath, namespace)...)

	// When a TopologyRef CR is referenced with an override to an instance of
	// OctaviaHealthManager, fail if a different Namespace is referenced
	// because not supported
	hmPath := basePath.Child("octaviaHealthManager")
	allErrs = append(allErrs, spec.OctaviaHealthManager.ValidateTopology(hmPath, namespace)...)

	// When a TopologyRef CR is referenced with an override to an instance of
	// OctaviaRsyslog, fail if a different Namespace is referenced
	// because not supported
	rsPath := basePath.Child("octaviaRsyslog")
	allErrs = append(allErrs, spec.OctaviaRsyslog.ValidateTopology(rsPath, namespace)...)

	// When a TopologyRef CR is referenced with an override to an instance of
	// OctaviaWorker, fail if a different Namespace is referenced
	// because not supported
	wPath := basePath.Child("octaviaWorker")
	allErrs = append(allErrs, spec.OctaviaWorker.ValidateTopology(wPath, namespace)...)

	return allErrs
}

// ValidateOctaviaTopology - Returns an ErrorList if the Topology is referenced
// on a different namespace
func (spec *OctaviaSpec) ValidateOctaviaTopology(basePath *field.Path, namespace string) field.ErrorList {
	var allErrs field.ErrorList

	// When a TopologyRef CR is referenced, fail if a different Namespace is
	// referenced because is not supported
	allErrs = append(allErrs, topologyv1.ValidateTopologyRef(
		spec.TopologyRef, *basePath.Child("topologyRef"), namespace)...)

	// When a TopologyRef CR is referenced with an override to OctaviaAPI, fail
	// if a different Namespace is referenced because not supported
	apiPath := basePath.Child("octaviaAPI")
	allErrs = append(allErrs, spec.OctaviaAPI.ValidateTopology(apiPath, namespace)...)

	// When a TopologyRef CR is referenced with an override to OctaviaHousekeeping,
	// fail if a different Namespace is referenced because not supported
	hkPath := basePath.Child("octaviaHousekeeping")
	allErrs = append(allErrs, spec.OctaviaHousekeeping.ValidateTopology(hkPath, namespace)...)

	// When a TopologyRef CR is referenced with an override to an instance of
	// OctaviaHealthManager, fail if a different Namespace is referenced
	// because not supported
	hmPath := basePath.Child("octaviaHealthManager")
	allErrs = append(allErrs, spec.OctaviaHealthManager.ValidateTopology(hmPath, namespace)...)

	// When a TopologyRef CR is referenced with an override to an instance of
	// OctaviaRsyslog, fail if a different Namespace is referenced
	// because not supported
	rsPath := basePath.Child("octaviaRsyslog")
	allErrs = append(allErrs, spec.OctaviaRsyslog.ValidateTopology(rsPath, namespace)...)

	// When a TopologyRef CR is referenced with an override to an instance of
	// OctaviaWorker, fail if a different Namespace is referenced
	// because not supported
	wPath := basePath.Child("octaviaWorker")
	allErrs = append(allErrs, spec.OctaviaWorker.ValidateTopology(wPath, namespace)...)

	return allErrs
}
