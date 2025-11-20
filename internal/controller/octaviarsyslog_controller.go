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

package controller

import (
	"context"
	"fmt"
	"maps"
	"time"

	"github.com/go-logr/logr"
	networkv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/openstack-k8s-operators/lib-common/modules/common"
	"github.com/openstack-k8s-operators/lib-common/modules/common/condition"
	"github.com/openstack-k8s-operators/lib-common/modules/common/daemonset"
	"github.com/openstack-k8s-operators/lib-common/modules/common/env"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	"github.com/openstack-k8s-operators/lib-common/modules/common/labels"
	nad "github.com/openstack-k8s-operators/lib-common/modules/common/networkattachment"
	"github.com/openstack-k8s-operators/lib-common/modules/common/util"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	topologyv1 "github.com/openstack-k8s-operators/infra-operator/apis/topology/v1beta1"
	oko_secret "github.com/openstack-k8s-operators/lib-common/modules/common/secret"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/octavia-operator/internal/octavia"
	"github.com/openstack-k8s-operators/octavia-operator/internal/octaviarsyslog"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// OctaviaRsyslogReconciler reconciles an OctaviaAmmphoraController object
type OctaviaRsyslogReconciler struct {
	client.Client
	Kclient kubernetes.Interface
	Scheme  *runtime.Scheme
}

// GetLogger returns a logger object with a prefix of "controller.name" and additional controller context fields
func (r *OctaviaRsyslogReconciler) GetLogger(ctx context.Context) logr.Logger {
	return log.FromContext(ctx).WithName("Controllers").WithName("OctaviaRsyslog")
}

//+kubebuilder:rbac:groups=octavia.openstack.org,resources=octaviarsyslogs,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=octavia.openstack.org,resources=octaviarsyslogs/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=octavia.openstack.org,resources=octaviarsyslogs/finalizers,verbs=update
// +kubebuilder:rbac:groups=k8s.cni.cncf.io,resources=network-attachment-definitions,verbs=get;list;watch
// +kubebuilder:rbac:groups="security.openshift.io",resourceNames=anyuid;privileged,resources=securitycontextconstraints,verbs=use
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups="rbac.authorization.k8s.io",resources=roles,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups="rbac.authorization.k8s.io",resources=rolebindings,verbs=get;list;watch;create;update
// service account permissions that are needed to grant permission to the above
// +kubebuilder:rbac:groups="",resources=pods,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups=topology.openstack.org,resources=topologies,verbs=get;list;watch;update

// Reconcile implementation of the reconcile loop for octavia rsyslog
func (r *OctaviaRsyslogReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, _err error) {
	Log := r.GetLogger(ctx)

	instance := &octaviav1.OctaviaRsyslog{}
	err := r.Get(ctx, req.NamespacedName, instance)
	if err != nil {
		if k8s_errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected.
			// For additional cleanup logic, use finalizers. Return and don't requeue.
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		Log.Error(err, fmt.Sprintf("could not fetch instance %s", instance.Name))
		return ctrl.Result{}, err
	}

	helper, err := helper.NewHelper(
		instance,
		r.Client,
		r.Kclient,
		r.Scheme,
		Log,
	)
	if err != nil {
		Log.Error(err, fmt.Sprintf("could not instantiate helper for instance %s", instance.Name))
		return ctrl.Result{}, err
	}

	// initialize status if Conditions is nil, but do not reset if it already
	// exists
	isNewInstance := instance.Status.Conditions == nil
	if isNewInstance {
		instance.Status.Conditions = condition.Conditions{}
	}

	// Save a copy of the condtions so that we can restore the LastTransitionTime
	// when a condition's state doesn't change.
	savedConditions := instance.Status.Conditions.DeepCopy()

	// Always patch the instance status when exiting this function so we can
	// persist any changes.
	defer func() {
		// Don't update the status, if reconciler Panics
		if r := recover(); r != nil {
			Log.Info(fmt.Sprintf("panic during reconcile %v\n", r))
			panic(r)
		}
		condition.RestoreLastTransitionTimes(
			&instance.Status.Conditions, savedConditions)
		if instance.Status.Conditions.IsUnknown(condition.ReadyCondition) {
			instance.Status.Conditions.Set(
				instance.Status.Conditions.Mirror(condition.ReadyCondition))
		}
		err := helper.PatchInstance(ctx, instance)
		if err != nil {
			_err = err
			return
		}
	}()

	// Setup the initial conditions
	cl := condition.CreateList(
		condition.UnknownCondition(condition.ReadyCondition, condition.InitReason, condition.ReadyInitMessage),
		condition.UnknownCondition(condition.ServiceConfigReadyCondition, condition.InitReason, condition.ServiceConfigReadyInitMessage),
		condition.UnknownCondition(condition.InputReadyCondition, condition.InitReason, condition.InputReadyInitMessage),
		condition.UnknownCondition(condition.DeploymentReadyCondition, condition.InitReason, condition.DeploymentReadyInitMessage),
		condition.UnknownCondition(condition.NetworkAttachmentsReadyCondition, condition.InitReason, condition.NetworkAttachmentsReadyInitMessage),
	)

	instance.Status.Conditions.Init(&cl)
	instance.Status.ObservedGeneration = instance.Generation

	// Init Topology condition if there's a reference
	if instance.Spec.TopologyRef != nil {
		c := condition.UnknownCondition(condition.TopologyReadyCondition, condition.InitReason, condition.TopologyReadyInitMessage)
		cl.Set(c)
	}

	// If we're not deleting this and the service object doesn't have our finalizer, add it.
	if instance.DeletionTimestamp.IsZero() && controllerutil.AddFinalizer(instance, helper.GetFinalizer()) || isNewInstance {
		return ctrl.Result{}, nil
	}

	// Handle service delete
	if !instance.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, instance, helper)
	}

	if instance.Status.Hash == nil {
		instance.Status.Hash = map[string]string{}
	}

	if instance.Status.NetworkAttachments == nil {
		instance.Status.NetworkAttachments = map[string][]string{}
	}

	// Handle non-deleted clusters
	return r.reconcileNormal(ctx, instance, helper)
}

func (r *OctaviaRsyslogReconciler) reconcileDelete(ctx context.Context, instance *octaviav1.OctaviaRsyslog,
	helper *helper.Helper) (ctrl.Result, error) {
	Log := r.GetLogger(ctx)
	Log.Info("Reconciling Service delete")

	// Remove finalizer on the Topology CR
	if ctrlResult, err := topologyv1.EnsureDeletedTopologyRef(
		ctx,
		helper,
		instance.Status.LastAppliedTopology,
		instance.Name,
	); err != nil {
		return ctrlResult, err
	}
	controllerutil.RemoveFinalizer(instance, helper.GetFinalizer())

	Log.Info("Reconciled Service delete successfully")
	return ctrl.Result{}, nil
}

func (r *OctaviaRsyslogReconciler) reconcileUpdate(ctx context.Context) (ctrl.Result, error) {
	Log := r.GetLogger(ctx)
	Log.Info("Reconciling Service update")
	Log.Info("Reconciled Service update successfully")
	return ctrl.Result{}, nil
}

func (r *OctaviaRsyslogReconciler) reconcileUpgrade(ctx context.Context) (ctrl.Result, error) {
	Log := r.GetLogger(ctx)
	Log.Info("Reconciling Service upgrade")
	Log.Info("Reconciled Service upgrade successfully")
	return ctrl.Result{}, nil
}

func (r *OctaviaRsyslogReconciler) reconcileNormal(ctx context.Context, instance *octaviav1.OctaviaRsyslog,
	helper *helper.Helper) (ctrl.Result, error) {
	Log := r.GetLogger(ctx)
	Log.Info("Reconciling Service")

	// Prepare NetworkAttachments first, it must be done before generating the
	// configuration as the config uses IP addresses of the attachments.
	if len(instance.Spec.NetworkAttachments) == 0 {
		err := octavia.ErrNetworkAttachmentsEmpty
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.NetworkAttachmentsReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			condition.NetworkAttachmentsReadyErrorMessage,
			err))
		return ctrl.Result{}, err
	}

	nadList := []networkv1.NetworkAttachmentDefinition{}
	for _, networkAttachment := range instance.Spec.NetworkAttachments {
		nad, err := nad.GetNADWithName(ctx, helper, networkAttachment, instance.Namespace)
		if err != nil {
			if k8s_errors.IsNotFound(err) {
				// Since the net-attach-def CR should have been manually created by the user and referenced in the spec,
				// we treat this as a warning because it means that the service will not be able to start.
				Log.Info(fmt.Sprintf("network-attachment-definition %s not found", networkAttachment))
				instance.Status.Conditions.Set(condition.FalseCondition(
					condition.NetworkAttachmentsReadyCondition,
					condition.ErrorReason,
					condition.SeverityWarning,
					condition.NetworkAttachmentsReadyWaitingMessage,
					networkAttachment))
				return ctrl.Result{RequeueAfter: time.Second * 10}, nil
			}
			instance.Status.Conditions.Set(condition.FalseCondition(
				condition.NetworkAttachmentsReadyCondition,
				condition.ErrorReason,
				condition.SeverityWarning,
				condition.NetworkAttachmentsReadyErrorMessage,
				err.Error()))
			return ctrl.Result{}, err
		}

		if nad != nil {
			nadList = append(nadList, *nad)
		}
	}

	serviceAnnotations, err := nad.EnsureNetworksAnnotation(nadList)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed create network annotation from %s: %w",
			instance.Spec.NetworkAttachments, err)
	}

	serviceLabels := map[string]string{
		common.AppSelector: instance.Name,
	}

	// Handle secrets
	secretsVars := make(map[string]env.Setter)

	err = r.generateServiceSecrets(ctx, instance, helper, &secretsVars)
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
	inputHash, err := r.createHashOfInputHashes(ctx, instance, secretsVars)
	if err != nil {
		return ctrl.Result{}, err
	}

	instance.Status.Conditions.MarkTrue(condition.ServiceConfigReadyCondition, condition.ServiceConfigReadyMessage)

	// Handle service update
	ctrlResult, err := r.reconcileUpdate(ctx)
	if err != nil {
		return ctrlResult, err
	} else if (ctrlResult != ctrl.Result{}) {
		return ctrlResult, nil
	}

	// Handle service upgrade
	ctrlResult, err = r.reconcileUpgrade(ctx)
	if err != nil {
		return ctrlResult, err
	} else if (ctrlResult != ctrl.Result{}) {
		return ctrlResult, nil
	}

	//
	// Handle Topology
	//
	topology, err := ensureTopology(
		ctx,
		helper,
		instance,      // topologyHandler
		instance.Name, // finalizer
		&instance.Status.Conditions,
		labels.GetLabelSelector(serviceLabels),
	)
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.TopologyReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			condition.TopologyReadyErrorMessage,
			err.Error()))
		return ctrl.Result{}, fmt.Errorf("waiting for Topology requirements: %w", err)
	}

	//
	// normal reconcile tasks
	//

	// Define a new DaemonSet object
	dset := daemonset.NewDaemonSet(
		octaviarsyslog.DaemonSet(
			instance,
			inputHash,
			serviceLabels,
			serviceAnnotations,
			topology,
		),
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

	if dset.GetDaemonSet().Generation == dset.GetDaemonSet().Status.ObservedGeneration {
		instance.Status.DesiredNumberScheduled = dset.GetDaemonSet().Status.DesiredNumberScheduled
		// TODO(gthiemonge) change for NumberReady?
		instance.Status.ReadyCount = dset.GetDaemonSet().Status.NumberReady

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
			err := fmt.Errorf("%w: %s", octavia.ErrNetworkAttachmentConfig, instance.Spec.NetworkAttachments)
			instance.Status.Conditions.Set(condition.FalseCondition(
				condition.NetworkAttachmentsReadyCondition,
				condition.ErrorReason,
				condition.SeverityWarning,
				condition.NetworkAttachmentsReadyErrorMessage,
				err.Error()))

			return ctrl.Result{RequeueAfter: time.Duration(1) * time.Second}, nil
		}

		if instance.Status.ReadyCount == instance.Status.DesiredNumberScheduled {
			instance.Status.Conditions.MarkTrue(condition.DeploymentReadyCondition, condition.DeploymentReadyMessage)
		}
	}
	// create DaemonSet - end

	// We reached the end of the Reconcile, update the Ready condition based on
	// the sub conditions
	if instance.Status.Conditions.AllSubConditionIsTrue() {
		instance.Status.Conditions.MarkTrue(
			condition.ReadyCondition, condition.ReadyMessage)
	} else {
		Log.Info("Not all conditions are ready for OctaviaRsyslog controller")
	}
	return ctrl.Result{}, nil
}

func (r *OctaviaRsyslogReconciler) generateServiceSecrets(
	ctx context.Context,
	instance *octaviav1.OctaviaRsyslog,
	helper *helper.Helper,
	envVars *map[string]env.Setter,
) error {
	Log := r.GetLogger(ctx)
	Log.Info(fmt.Sprintf("generating service config map for %s (%s)", instance.Name, instance.Kind))
	cmLabels := labels.GetLabels(instance, labels.GetGroupLabel(instance.Name), map[string]string{})

	customData := map[string]string{}
	maps.Copy(customData, instance.Spec.DefaultConfigOverwrite)

	templateParameters := map[string]any{}
	templateParameters["AdminLogTargets"] = instance.Spec.AdminLogTargets
	templateParameters["TenantLogTargets"] = instance.Spec.TenantLogTargets

	spec := instance.Spec
	templateParameters["ServiceUser"] = spec.ServiceUser

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

	err := oko_secret.EnsureSecrets(ctx, helper, instance, cms, envVars)
	if err != nil {
		Log.Error(err, "unable to process config map")
		return err
	}

	Log.Info("Service config map generated")

	return nil
}

func (r *OctaviaRsyslogReconciler) createHashOfInputHashes(
	ctx context.Context,
	instance *octaviav1.OctaviaRsyslog,
	envVars map[string]env.Setter,
) (string, error) {
	Log := r.GetLogger(ctx)
	mergedMapVars := env.MergeEnvs([]corev1.EnvVar{}, envVars)
	hash, err := util.ObjectHash(mergedMapVars)
	if err != nil {
		return hash, err
	}

	if hashMap, changed := util.SetHash(instance.Status.Hash, common.InputHashName, hash); changed {
		instance.Status.Hash = hashMap
		Log.Info(fmt.Sprintf("Input maps hash %s - %s", common.InputHashName, hash))
	}
	return hash, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *OctaviaRsyslogReconciler) SetupWithManager(mgr ctrl.Manager) error {

	// index topologyField
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &octaviav1.OctaviaRsyslog{}, topologyField, func(rawObj client.Object) []string {
		// Extract the topology name from the spec, if one is provided
		cr := rawObj.(*octaviav1.OctaviaRsyslog)
		if cr.Spec.TopologyRef == nil {
			return nil
		}
		return []string{cr.Spec.TopologyRef.Name}
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&octaviav1.OctaviaRsyslog{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&appsv1.DaemonSet{}).
		Watches(&topologyv1.Topology{},
			handler.EnqueueRequestsFromMapFunc(r.findObjectsForSrc),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

func (r *OctaviaRsyslogReconciler) findObjectsForSrc(ctx context.Context, src client.Object) []reconcile.Request {
	requests := []reconcile.Request{}

	Log := r.GetLogger(ctx)

	for _, field := range rsyslogWatchFields {
		crList := &octaviav1.OctaviaAPIList{}
		listOps := &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(field, src.GetName()),
			Namespace:     src.GetNamespace(),
		}
		err := r.List(ctx, crList, listOps)
		if err != nil {
			Log.Error(err, fmt.Sprintf("listing %s for field: %s - %s", crList.GroupVersionKind().Kind, field, src.GetNamespace()))
			return requests
		}

		for _, item := range crList.Items {
			Log.Info(fmt.Sprintf("input source %s changed, reconcile: %s - %s", src.GetName(), item.GetName(), item.GetNamespace()))

			requests = append(requests,
				reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      item.GetName(),
						Namespace: item.GetNamespace(),
					},
				},
			)
		}
	}

	return requests
}
