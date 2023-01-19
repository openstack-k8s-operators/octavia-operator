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

package controllers

import (
	"context"
	"fmt"

	"github.com/openstack-k8s-operators/lib-common/modules/common/condition"

	"github.com/go-logr/logr"
	"github.com/openstack-k8s-operators/lib-common/modules/common"
	"github.com/openstack-k8s-operators/lib-common/modules/common/configmap"
	"github.com/openstack-k8s-operators/lib-common/modules/common/deployment"
	"github.com/openstack-k8s-operators/lib-common/modules/common/env"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	"github.com/openstack-k8s-operators/lib-common/modules/common/labels"
	"github.com/openstack-k8s-operators/lib-common/modules/common/util"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	mariadbv1 "github.com/openstack-k8s-operators/mariadb-operator/api/v1beta1"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/octavia-operator/pkg/amphoracontrollers"
	"github.com/openstack-k8s-operators/octavia-operator/pkg/octavia"
)

// OctaviaHousekeepingReconciler reconciles a OctaviaHousekeeping object
type OctaviaHousekeepingReconciler struct {
	client.Client
	Kclient kubernetes.Interface
	Log     logr.Logger
	Scheme  *runtime.Scheme
}

//+kubebuilder:rbac:groups=octavia.openstack.org,resources=octaviahousekeepings,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=octavia.openstack.org,resources=octaviahousekeepings/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=octavia.openstack.org,resources=octaviahousekeepings/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the OctaviaHousekeeping object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.1/pkg/reconcile
func (r *OctaviaHousekeepingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = r.Log.WithValues("octaviahousekeeping", req.NamespacedName)

	instance := &octaviav1.OctaviaHousekeeping{}
	err := r.Client.Get(ctx, req.NamespacedName, instance)
	if err != nil {
		if k8s_errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected.
			// For additional cleanup logic, use finalizers. Return and don't requeue.
			return ctrl.Result{}, nil
		}
		// Error reading the object, requeue the request
		return ctrl.Result{}, err
	}

	if instance.Status.Conditions == nil {
		// Setup the initial conditions
		instance.Status.Conditions = condition.Conditions{}
		cl := condition.CreateList(
			condition.UnknownCondition(condition.ExposeServiceReadyCondition, condition.InitReason, condition.ExposeServiceReadyInitMessage),
			condition.UnknownCondition(condition.ServiceConfigReadyCondition, condition.InitReason, condition.ServiceConfigReadyInitMessage),
			condition.UnknownCondition(condition.InputReadyCondition, condition.InitReason, condition.InputReadyInitMessage),
			condition.UnknownCondition(condition.DeploymentReadyCondition, condition.InitReason, condition.DeploymentReadyInitMessage),
		)
		// TODO(beagles): what other conditions?
		instance.Status.Conditions.Init(&cl)
		if err := r.Status().Update(ctx, instance); err != nil {
			return ctrl.Result{}, err
		}
	}

	if instance.Status.Hash == nil {
		instance.Status.Hash = map[string]string{}
	}

	helper, err := helper.NewHelper(
		instance,
		r.Client,
		r.Kclient,
		r.Scheme,
		r.Log,
	)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Always patch the instance status when exiting this function so we can persist any changes.
	defer func() {
		// update the overall status condition if service is ready
		if instance.IsReady() {
			instance.Status.Conditions.MarkTrue(condition.ReadyCondition, condition.ReadyMessage)
		}

		if err := helper.SetAfter(instance); err != nil {
			util.LogErrorForObject(helper, err, "Set after and calc patch/diff", instance)
		}

		if changed := helper.GetChanges()["status"]; changed {
			patch := client.MergeFrom(helper.GetBeforeObject())

			if err := r.Status().Patch(ctx, instance, patch); err != nil && !k8s_errors.IsNotFound(err) {
				util.LogErrorForObject(helper, err, "Update status", instance)
			}
		}
	}()

	// Handle service delete
	if !instance.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, instance, helper)
	}

	// Handle non-deleted clusters
	return r.reconcileNormal(ctx, instance, helper)
}

func (r *OctaviaHousekeepingReconciler) reconcileDelete(ctx context.Context, instance *octaviav1.OctaviaHousekeeping, helper *helper.Helper) (ctrl.Result, error) {
	util.LogForObject(helper, "Reconciling Service delete", instance)

	controllerutil.RemoveFinalizer(instance, helper.GetFinalizer())

	if err := r.Update(ctx, instance); err != nil && !k8s_errors.IsNotFound(err) {
		return ctrl.Result{}, err
	}

	util.LogForObject(helper, "Reconciled Service delete successfully", instance)
	return ctrl.Result{}, nil
}

func (r *OctaviaHousekeepingReconciler) reconcileUpdate(ctx context.Context, instance *octaviav1.OctaviaHousekeeping, helper *helper.Helper) (ctrl.Result, error) {
	util.LogForObject(helper, "Reconciling Service update", instance)
	util.LogForObject(helper, "Reconciled Service update successfully", instance)
	return ctrl.Result{}, nil
}

func (r *OctaviaHousekeepingReconciler) reconcileUpgrade(ctx context.Context, instance *octaviav1.OctaviaHousekeeping, helper *helper.Helper) (ctrl.Result, error) {
	util.LogForObject(helper, "Reconciling Service upgrade", instance)
	util.LogForObject(helper, "Reconciled Service upgrade successfully", instance)
	return ctrl.Result{}, nil
}

func (r *OctaviaHousekeepingReconciler) reconcileNormal(ctx context.Context, instance *octaviav1.OctaviaHousekeeping, helper *helper.Helper) (ctrl.Result, error) {
	util.LogForObject(helper, "Reconciling Service", instance)
	if !controllerutil.ContainsFinalizer(instance, helper.GetFinalizer()) {
		// If the service object doesn't have our finalizer, add it.
		controllerutil.AddFinalizer(instance, helper.GetFinalizer())
		// Register the finalizer immediately to avoid orphaning resources on delete
		err := r.Update(ctx, instance)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	// Handle config map
	configMapVars := make(map[string]env.Setter)
	err := r.generateServiceConfigMaps(ctx, instance, helper, &configMapVars)
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.ServiceConfigReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			condition.ServiceConfigReadyErrorMessage,
			err.Error()))
		return ctrl.Result{}, err
	}

	//
	// create hash over all the different input resources to identify if any those changed
	// and a restart/recreate is required.
	//
	inputHash, err := r.createHashOfInputHashes(ctx, instance, configMapVars)
	if err != nil {
		return ctrl.Result{}, err
	}

	instance.Status.Conditions.MarkTrue(condition.ServiceConfigReadyCondition, condition.ServiceConfigReadyMessage)

	// Handle service update
	ctrlResult, err := r.reconcileUpdate(ctx, instance, helper)
	if err != nil {
		return ctrlResult, err
	} else if (ctrlResult != ctrl.Result{}) {
		return ctrlResult, nil
	}

	// Handle service upgrade
	ctrlResult, err = r.reconcileUpgrade(ctx, instance, helper)
	if err != nil {
		return ctrlResult, err
	} else if (ctrlResult != ctrl.Result{}) {
		return ctrlResult, nil
	}

	//
	// normal reconcile tasks
	//

	serviceLabels := map[string]string{
		common.AppSelector: octavia.ServiceName,
	}

	// Define a new Deployment object
	depl := deployment.NewDeployment(
		amphoracontrollers.AmphoraControllerDeployment(&instance.ObjectMeta, &instance.Spec.AmphoraControllerBaseSpec, inputHash, "housekeeping", serviceLabels),
		5,
	)

	ctrlResult, err = depl.CreateOrPatch(ctx, helper)
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.DeploymentReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			condition.DeploymentReadyErrorMessage,
			err.Error()))
		return ctrlResult, err
	} else if (ctrlResult != ctrl.Result{}) {
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.DeploymentReadyCondition,
			condition.RequestedReason,
			condition.SeverityInfo,
			condition.DeploymentReadyRunningMessage))
		return ctrlResult, nil
	}
	instance.Status.ReadyCount = depl.GetDeployment().Status.ReadyReplicas
	if instance.Status.ReadyCount > 0 {
		instance.Status.Conditions.MarkTrue(condition.DeploymentReadyCondition, condition.DeploymentReadyMessage)
	}
	// create Deployment - end

	util.LogForObject(helper, "Reconciled Service successfully", instance)
	return ctrl.Result{}, nil
}

func (r *OctaviaHousekeepingReconciler) generateServiceConfigMaps(
	ctx context.Context,
	instance *octaviav1.OctaviaHousekeeping,
	helper *helper.Helper,
	envVars *map[string]env.Setter,
) error {
	cmLabels := labels.GetLabels(instance, labels.GetGroupLabel(octavia.ServiceName), map[string]string{})
	customData := map[string]string{common.CustomServiceConfigFileName: instance.Spec.CustomServiceConfig}
	for key, data := range instance.Spec.DefaultConfigOverwrite {
		customData[key] = data
	}
	templateParameters := make(map[string]interface{})

	// TODO(beagles): populate the template parameters
	cms := []util.Template{
		// ScriptsConfigMap
		{
			Name:               fmt.Sprintf("%s-scripts", instance.Name),
			Namespace:          instance.Namespace,
			Type:               util.TemplateTypeScripts,
			InstanceType:       instance.Kind,
			AdditionalTemplate: map[string]string{"common.sh": "/common/common.sh"},
			Labels:             cmLabels,
		},
		{
			Name:          fmt.Sprintf("%s-config-data", instance.Name),
			Namespace:     instance.Namespace,
			Type:          util.TemplateTypeConfig,
			InstanceType:  instance.Kind,
			CustomData:    customData,
			ConfigOptions: templateParameters,
			Labels:        cmLabels,
		},
	}

	err := configmap.EnsureConfigMaps(ctx, helper, instance, cms, envVars)
	if err != nil {
		return nil
	}

	return nil
}

func (r *OctaviaHousekeepingReconciler) createHashOfInputHashes(
	ctx context.Context,
	instance *octaviav1.OctaviaHousekeeping,
	envVars map[string]env.Setter,
) (string, error) {
	mergedMapVars := env.MergeEnvs([]corev1.EnvVar{}, envVars)
	hash, err := util.ObjectHash(mergedMapVars)
	if err != nil {
		return hash, err
	}

	if hashMap, changed := util.SetHash(instance.Status.Hash, common.InputHashName, hash); changed {
		instance.Status.Hash = hashMap
		if err := r.Client.Status().Update(ctx, instance); err != nil {
			return hash, err
		}
		r.Log.Info(fmt.Sprintf("Input maps hash %s - %s", common.InputHashName, hash))
	}
	return hash, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *OctaviaHousekeepingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// TODO: OctaviaAPI contains db init code, might be better to put with a
	// a common controller.
	return ctrl.NewControllerManagedBy(mgr).
		For(&octaviav1.OctaviaHousekeeping{}).
		Owns(&mariadbv1.MariaDBDatabase{}).
		Owns(&octaviav1.OctaviaAPI{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&appsv1.Deployment{}).
		Complete(r)
}
