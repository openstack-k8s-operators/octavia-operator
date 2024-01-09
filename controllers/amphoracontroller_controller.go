/*
Copyright 2023.

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
	"time"

	"github.com/go-logr/logr"
	"github.com/openstack-k8s-operators/lib-common/modules/common"
	"github.com/openstack-k8s-operators/lib-common/modules/common/condition"
	"github.com/openstack-k8s-operators/lib-common/modules/common/configmap"
	"github.com/openstack-k8s-operators/lib-common/modules/common/daemonset"
	"github.com/openstack-k8s-operators/lib-common/modules/common/endpoint"
	"github.com/openstack-k8s-operators/lib-common/modules/common/env"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	"github.com/openstack-k8s-operators/lib-common/modules/common/labels"
	nad "github.com/openstack-k8s-operators/lib-common/modules/common/networkattachment"
	"github.com/openstack-k8s-operators/lib-common/modules/common/secret"
	"github.com/openstack-k8s-operators/lib-common/modules/common/util"

	keystonev1 "github.com/openstack-k8s-operators/keystone-operator/api/v1beta1"
	oko_secret "github.com/openstack-k8s-operators/lib-common/modules/common/secret"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/octavia-operator/pkg/amphoracontrollers"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// OctaviaAmphoraControllerReconciler reconciles an OctaviaAmmphoraController object
type OctaviaAmphoraControllerReconciler struct {
	client.Client
	Kclient kubernetes.Interface
	Log     logr.Logger
	Scheme  *runtime.Scheme
}

// OctaviaTemplateVars structure that contains generated parameters for the service config files
type OctaviaTemplateVars struct {
	LbMgmtNetworkID        string
	AmphoraDefaultFlavorID string
}

// GetLogger returns a logger object with a prefix of "controller.name" and additional controller context fields
func (r *OctaviaAmphoraControllerReconciler) GetLogger(ctx context.Context) logr.Logger {
	return log.FromContext(ctx).WithName("Controllers").WithName("OctaviaAmphoraController")
}

//+kubebuilder:rbac:groups=octavia.openstack.org,resources=octaviaamphoracontrollers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=octavia.openstack.org,resources=octaviaamphoracontrollers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=octavia.openstack.org,resources=octaviaamphoracontrollers/finalizers,verbs=update
// +kubebuilder:rbac:groups=k8s.cni.cncf.io,resources=network-attachment-definitions,verbs=get;list;watch
// +kubebuilder:rbac:groups="security.openshift.io",resourceNames=anyuid;privileged,resources=securitycontextconstraints,verbs=use
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups="rbac.authorization.k8s.io",resources=roles,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups="rbac.authorization.k8s.io",resources=rolebindings,verbs=get;list;watch;create;update
// service account permissions that are needed to grant permission to the above
// +kubebuilder:rbac:groups="",resources=pods,verbs=create;delete;get;list;patch;update;watch

// Reconcile implementation of the reconcile loop for amphora
// controllers like the octavia housekeeper, worker and health manager
// services
func (r *OctaviaAmphoraControllerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	Log := r.GetLogger(ctx)

	instance := &octaviav1.OctaviaAmphoraController{}
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
			condition.UnknownCondition(condition.NetworkAttachmentsReadyCondition, condition.InitReason, condition.NetworkAttachmentsReadyInitMessage),
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

	if instance.Status.NetworkAttachments == nil {
		instance.Status.NetworkAttachments = map[string][]string{}
	}

	helper, err := helper.NewHelper(
		instance,
		r.Client,
		r.Kclient,
		r.Scheme,
		Log,
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
			Log.Error(err, "Set after and calc patch/diff")
		}

		if changed := helper.GetChanges()["status"]; changed {
			patch := client.MergeFrom(helper.GetBeforeObject())

			if err := r.Status().Patch(ctx, instance, patch); err != nil && !k8s_errors.IsNotFound(err) {
				Log.Error(err, "Update status")
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

func (r *OctaviaAmphoraControllerReconciler) reconcileDelete(ctx context.Context, instance *octaviav1.OctaviaAmphoraController,
	helper *helper.Helper) (ctrl.Result, error) {
	Log := r.GetLogger(ctx)
	Log.Info("Reconciling Service delete")

	controllerutil.RemoveFinalizer(instance, helper.GetFinalizer())

	if err := r.Update(ctx, instance); err != nil && !k8s_errors.IsNotFound(err) {
		return ctrl.Result{}, err
	}

	Log.Info("Reconciled Service delete successfully")
	return ctrl.Result{}, nil
}

func (r *OctaviaAmphoraControllerReconciler) reconcileUpdate(ctx context.Context, instance *octaviav1.OctaviaAmphoraController,
	helper *helper.Helper) (ctrl.Result, error) {
	Log := r.GetLogger(ctx)
	Log.Info("Reconciling Service update")
	Log.Info("Reconciled Service update successfully")
	return ctrl.Result{}, nil
}

func (r *OctaviaAmphoraControllerReconciler) reconcileUpgrade(ctx context.Context, instance *octaviav1.OctaviaAmphoraController,
	helper *helper.Helper) (ctrl.Result, error) {
	Log := r.GetLogger(ctx)
	Log.Info("Reconciling Service upgrade")
	Log.Info("Reconciled Service upgrade successfully")
	return ctrl.Result{}, nil
}

func (r *OctaviaAmphoraControllerReconciler) reconcileNormal(ctx context.Context, instance *octaviav1.OctaviaAmphoraController,
	helper *helper.Helper) (ctrl.Result, error) {
	Log := r.GetLogger(ctx)
	Log.Info("Reconciling Service")
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

	ospSecret, hash, err := oko_secret.GetSecret(ctx, helper, instance.Spec.Secret, instance.Namespace)
	if err != nil {
		if k8s_errors.IsNotFound(err) {
			instance.Status.Conditions.Set(condition.FalseCondition(
				condition.InputReadyCondition,
				condition.RequestedReason,
				condition.SeverityInfo,
				condition.InputReadyWaitingMessage))
			return ctrl.Result{RequeueAfter: time.Duration(10) * time.Second}, fmt.Errorf("OpenStack secret %s not found", instance.Spec.Secret)
		}
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.InputReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			condition.InputReadyErrorMessage,
			err.Error()))
		return ctrl.Result{}, err
	}
	configMapVars[ospSecret.Name] = env.SetValue(hash)

	transportURLSecret, hash, err := oko_secret.GetSecret(ctx, helper, instance.Spec.TransportURLSecret, instance.Namespace)
	if err != nil {
		if k8s_errors.IsNotFound(err) {
			instance.Status.Conditions.Set(condition.FalseCondition(
				condition.InputReadyCondition,
				condition.RequestedReason,
				condition.SeverityInfo,
				condition.InputReadyWaitingMessage))
			return ctrl.Result{RequeueAfter: time.Duration(10) * time.Second}, fmt.Errorf("TransportURL secret %s not found", instance.Spec.TransportURLSecret)
		}
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.InputReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			condition.InputReadyErrorMessage,
			err.Error()))
		return ctrl.Result{}, err
	}
	configMapVars[transportURLSecret.Name] = env.SetValue(hash)

	// Create load balancer management network and get its Id
	networkID, err := amphoracontrollers.EnsureLbMgmtNetworks(ctx, instance, &r.Log, helper)
	if err != nil {
		return ctrl.Result{}, err
	}
	r.Log.Info(fmt.Sprintf("Using management network \"%s\"", networkID))

	defaultFlavorID, err := amphoracontrollers.EnsureFlavors(ctx, instance, &r.Log, helper)
	if err != nil {
		return ctrl.Result{}, err
	}
	r.Log.Info(fmt.Sprintf("Using default flavor \"%s\"", defaultFlavorID))

	templateVars := OctaviaTemplateVars{
		LbMgmtNetworkID:        networkID,
		AmphoraDefaultFlavorID: defaultFlavorID,
	}

	err = r.generateServiceConfigMaps(ctx, instance, helper, &configMapVars, templateVars, ospSecret)
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.ServiceConfigReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			condition.ServiceConfigReadyErrorMessage,
			err.Error()))
		return ctrl.Result{}, err
	}

	err = amphoracontrollers.EnsureAmphoraCerts(ctx, instance, helper, &Log)
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.ServiceConfigReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			condition.ServiceConfigReadyErrorMessage,
			err.Error()))
		return ctrl.Result{}, err
	}

	err = amphoracontrollers.EnsureAmpSSHConfig(ctx, instance, helper, &Log)
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.ServiceConfigReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			condition.ServiceConfigReadyErrorMessage,
			err.Error()))
		return ctrl.Result{}, err
	}

	instance.Status.Conditions.MarkTrue(condition.InputReadyCondition, condition.InputReadyMessage)

	//
	// create hash over all the different input resources to identify if any those changed
	// and a restart/recreate is required.
	//
	inputHash, err := r.createHashOfInputHashes(ctx, instance, configMapVars)
	if err != nil {
		return ctrl.Result{}, err
	}

	instance.Status.Conditions.MarkTrue(condition.ServiceConfigReadyCondition, condition.ServiceConfigReadyMessage)

	for _, networkAttachment := range instance.Spec.NetworkAttachments {
		_, err := nad.GetNADWithName(ctx, helper, networkAttachment, instance.Namespace)
		if err != nil {
			if k8s_errors.IsNotFound(err) {
				instance.Status.Conditions.Set(condition.FalseCondition(
					condition.NetworkAttachmentsReadyCondition,
					condition.RequestedReason,
					condition.SeverityInfo,
					condition.NetworkAttachmentsReadyWaitingMessage,
					networkAttachment))
				return ctrl.Result{RequeueAfter: time.Second * 10}, fmt.Errorf("network-attachment-definition %s not found", networkAttachment)
			}
			instance.Status.Conditions.Set(condition.FalseCondition(
				condition.NetworkAttachmentsReadyCondition,
				condition.ErrorReason,
				condition.SeverityWarning,
				condition.NetworkAttachmentsReadyErrorMessage,
				err.Error()))
			return ctrl.Result{}, err
		}
	}

	serviceAnnotations, err := nad.CreateNetworksAnnotation(instance.Namespace, instance.Spec.NetworkAttachments)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed create network annotation from %s: %w",
			instance.Spec.NetworkAttachments, err)
	}

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
		common.AppSelector: instance.ObjectMeta.Name,
	}

	// Define a new DaemonSet object
	dset := daemonset.NewDaemonSet(
		amphoracontrollers.DaemonSet(
			instance,
			inputHash,
			serviceLabels,
			serviceAnnotations),
		5,
	)

	ctrlResult, err = dset.CreateOrPatch(ctx, helper)
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

	// verify if network attachment matches expectations
	networkReady, networkAttachmentStatus, err := nad.VerifyNetworkStatusFromAnnotation(
		ctx,
		helper,
		instance.Spec.NetworkAttachments,
		serviceLabels,
		instance.Status.ReadyCount,
	)
	if err != nil {
		return ctrl.Result{}, err
	}

	instance.Status.NetworkAttachments = networkAttachmentStatus
	if networkReady {
		instance.Status.Conditions.MarkTrue(condition.NetworkAttachmentsReadyCondition, condition.NetworkAttachmentsReadyMessage)
	} else {
		err := fmt.Errorf("not all pods have interfaces with ips as configured in NetworkAttachments: %s", instance.Spec.NetworkAttachments)
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.NetworkAttachmentsReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			condition.NetworkAttachmentsReadyErrorMessage,
			err.Error()))

		return ctrl.Result{}, err
	}

	instance.Status.DesiredNumberScheduled = dset.GetDaemonSet().Status.DesiredNumberScheduled
	// TODO(gthiemonge) change for NumberReady?
	instance.Status.ReadyCount = dset.GetDaemonSet().Status.NumberReady
	if instance.Status.ReadyCount == instance.Status.DesiredNumberScheduled {
		instance.Status.Conditions.MarkTrue(condition.DeploymentReadyCondition, condition.DeploymentReadyMessage)
	}

	// create DaemonSet - end

	Log.Info("Reconciled Service successfully")
	return ctrl.Result{}, nil
}

func (r *OctaviaAmphoraControllerReconciler) generateServiceConfigMaps(
	ctx context.Context,
	instance *octaviav1.OctaviaAmphoraController,
	helper *helper.Helper,
	envVars *map[string]env.Setter,
	templateVars OctaviaTemplateVars,
	ospSecret *corev1.Secret,
) error {
	r.Log.Info(fmt.Sprintf("generating service config map for %s (%s)", instance.Name, instance.Kind))
	cmLabels := labels.GetLabels(instance, labels.GetGroupLabel(instance.ObjectMeta.Name), map[string]string{})
	customData := map[string]string{common.CustomServiceConfigFileName: instance.Spec.CustomServiceConfig}
	for key, data := range instance.Spec.DefaultConfigOverwrite {
		customData[key] = data
	}
	templateParameters := make(map[string]interface{})

	keystoneAPI, err := keystonev1.GetKeystoneAPI(ctx, helper, instance.Namespace, map[string]string{})
	if err != nil {
		return err
	}
	keystoneInternalURL, err := keystoneAPI.GetEndpoint(endpoint.EndpointInternal)
	if err != nil {
		return err
	}
	keystonePublicURL, err := keystoneAPI.GetEndpoint(endpoint.EndpointPublic)
	if err != nil {
		return err
	}
	caPassSecret, _, err := secret.GetSecret(
		ctx, helper, instance.Spec.CAKeyPassphraseSecret, instance.Namespace)
	if err != nil {
		return err
	}
	spec := instance.Spec
	templateParameters["ServiceUser"] = spec.ServiceUser
	templateParameters["KeystoneInternalURL"] = keystoneInternalURL
	templateParameters["KeystonePublicURL"] = keystonePublicURL
	templateParameters["ServiceRoleName"] = spec.Role
	templateParameters["LbMgmtNetworkId"] = templateVars.LbMgmtNetworkID
	templateParameters["AmpFlavorId"] = templateVars.AmphoraDefaultFlavorID
	templateParameters["NovaSshKeyPair"] = amphoracontrollers.NovaKeyPairName
	serverCAPassphrase := caPassSecret.Data["server-ca-passphrase"]
	if serverCAPassphrase != nil {
		templateParameters["ServerCAKeyPassphrase"] = string(serverCAPassphrase)
	} else {
		// Can't do string(nil)
		templateParameters["ServerCAKeyPassphrase"] = ""
	}
	// TODO(gthiemonge) store keys/passwords/passphrases in a specific config file stored in a secret
	templateParameters["HeartbeatKey"] = string(ospSecret.Data["OctaviaHeartbeatKey"])

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

	err = configmap.EnsureConfigMaps(ctx, helper, instance, cms, envVars)
	if err != nil {
		r.Log.Error(err, "unable to process config map")
		return err
	}

	r.Log.Info("Service config map generated")

	return nil
}

func (r *OctaviaAmphoraControllerReconciler) createHashOfInputHashes(
	ctx context.Context,
	instance *octaviav1.OctaviaAmphoraController,
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
func (r *OctaviaAmphoraControllerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&octaviav1.OctaviaAmphoraController{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&appsv1.DaemonSet{}).
		Complete(r)
}
