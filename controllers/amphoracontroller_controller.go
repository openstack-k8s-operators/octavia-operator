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
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/openstack-k8s-operators/lib-common/modules/common"
	"github.com/openstack-k8s-operators/lib-common/modules/common/condition"
	"github.com/openstack-k8s-operators/lib-common/modules/common/daemonset"
	"github.com/openstack-k8s-operators/lib-common/modules/common/endpoint"
	"github.com/openstack-k8s-operators/lib-common/modules/common/env"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	"github.com/openstack-k8s-operators/lib-common/modules/common/labels"
	nad "github.com/openstack-k8s-operators/lib-common/modules/common/networkattachment"
	"github.com/openstack-k8s-operators/lib-common/modules/common/tls"
	"github.com/openstack-k8s-operators/lib-common/modules/common/util"
	mariadbv1 "github.com/openstack-k8s-operators/mariadb-operator/api/v1beta1"

	keystonev1 "github.com/openstack-k8s-operators/keystone-operator/api/v1beta1"
	oko_secret "github.com/openstack-k8s-operators/lib-common/modules/common/secret"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/octavia-operator/pkg/amphoracontrollers"
	"github.com/openstack-k8s-operators/octavia-operator/pkg/octavia"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
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
	LbSecurityGroupID      string
}

// GetLogger returns a logger object with a prefix of "controller.name" and additional controller context fields
func (r *OctaviaAmphoraControllerReconciler) GetLogger(ctx context.Context) logr.Logger {
	return log.FromContext(ctx).WithName("Controllers").WithName("OctaviaAmphoraController")
}

//+kubebuilder:rbac:groups=octavia.openstack.org,resources=octaviaamphoracontrollers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=octavia.openstack.org,resources=octaviaamphoracontrollers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=octavia.openstack.org,resources=octaviaamphoracontrollers/finalizers,verbs=update;patch
// +kubebuilder:rbac:groups=k8s.cni.cncf.io,resources=network-attachment-definitions,verbs=get;list;watch
// +kubebuilder:rbac:groups="security.openshift.io",resourceNames=anyuid;privileged,resources=securitycontextconstraints,verbs=use
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="rbac.authorization.k8s.io",resources=roles,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="rbac.authorization.k8s.io",resources=rolebindings,verbs=get;list;watch;create;update;patch
// service account permissions that are needed to grant permission to the above
// +kubebuilder:rbac:groups="",resources=pods,verbs=create;delete;get;list;patch;update;watch;patch
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list

// Reconcile implementation of the reconcile loop for amphora
// controllers like the octavia housekeeper, worker and health manager
// services
func (r *OctaviaAmphoraControllerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, _err error) {
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
		condition.UnknownCondition(condition.TLSInputReadyCondition, condition.InitReason, condition.InputReadyInitMessage),
	)

	instance.Status.Conditions.Init(&cl)
	instance.Status.ObservedGeneration = instance.Generation

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

func (r *OctaviaAmphoraControllerReconciler) reconcileDelete(ctx context.Context, instance *octaviav1.OctaviaAmphoraController,
	helper *helper.Helper) (ctrl.Result, error) {
	Log := r.GetLogger(ctx)
	Log.Info("Reconciling Service delete")

	controllerutil.RemoveFinalizer(instance, helper.GetFinalizer())

	Log.Info("Reconciled Service delete successfully")
	return ctrl.Result{}, nil
}

func (r *OctaviaAmphoraControllerReconciler) reconcileUpdate(ctx context.Context) (ctrl.Result, error) {
	Log := r.GetLogger(ctx)
	Log.Info("Reconciling Service update")
	Log.Info("Reconciled Service update successfully")
	return ctrl.Result{}, nil
}

func (r *OctaviaAmphoraControllerReconciler) reconcileUpgrade(ctx context.Context) (ctrl.Result, error) {
	Log := r.GetLogger(ctx)
	Log.Info("Reconciling Service upgrade")
	Log.Info("Reconciled Service upgrade successfully")
	return ctrl.Result{}, nil
}

func (r *OctaviaAmphoraControllerReconciler) reconcileNormal(ctx context.Context, instance *octaviav1.OctaviaAmphoraController,
	helper *helper.Helper) (ctrl.Result, error) {
	Log := r.GetLogger(ctx)
	Log.Info("Reconciling Service")

	// Prepare NetworkAttachments first, it must be done before generating the
	// configuration as the config uses IP addresses of the attachments.
	if len(instance.Spec.NetworkAttachments) == 0 {
		err := fmt.Errorf("NetworkAttachments list is empty")
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.NetworkAttachmentsReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			condition.NetworkAttachmentsReadyErrorMessage,
			err))
		return ctrl.Result{}, err
	}

	for _, networkAttachment := range instance.Spec.NetworkAttachments {
		_, err := nad.GetNADWithName(ctx, helper, networkAttachment, instance.Namespace)
		if err != nil {
			if k8s_errors.IsNotFound(err) {
				Log.Info(fmt.Sprintf("network-attachment-definition %s not found", networkAttachment))
				instance.Status.Conditions.Set(condition.FalseCondition(
					condition.NetworkAttachmentsReadyCondition,
					condition.RequestedReason,
					condition.SeverityInfo,
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
	}

	serviceAnnotations, err := nad.CreateNetworksAnnotation(instance.Namespace, instance.Spec.NetworkAttachments)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed create network annotation from %s: %w",
			instance.Spec.NetworkAttachments, err)
	}

	serviceLabels := map[string]string{
		common.AppSelector: instance.ObjectMeta.Name,
	}

	// Handle config map
	configMapVars := make(map[string]env.Setter)

	ospSecret, hash, err := oko_secret.GetSecret(ctx, helper, instance.Spec.Secret, instance.Namespace)
	if err != nil {
		if k8s_errors.IsNotFound(err) {
			Log.Info(fmt.Sprintf("OpenStack secret %s not found", instance.Spec.Secret))
			instance.Status.Conditions.Set(condition.FalseCondition(
				condition.InputReadyCondition,
				condition.RequestedReason,
				condition.SeverityInfo,
				condition.InputReadyWaitingMessage))
			return ctrl.Result{RequeueAfter: time.Duration(10) * time.Second}, nil
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
			Log.Info(fmt.Sprintf("TransportURL secret %s not found", instance.Spec.TransportURLSecret))
			instance.Status.Conditions.Set(condition.FalseCondition(
				condition.InputReadyCondition,
				condition.RequestedReason,
				condition.SeverityInfo,
				condition.InputReadyWaitingMessage))
			return ctrl.Result{RequeueAfter: time.Duration(10) * time.Second}, nil
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

	defaultFlavorID, err := amphoracontrollers.EnsureFlavors(ctx, instance, &r.Log, helper)
	if err != nil {
		return ctrl.Result{}, err
	}
	r.Log.Info(fmt.Sprintf("Using default flavor \"%s\"", defaultFlavorID))

	templateVars := OctaviaTemplateVars{
		LbMgmtNetworkID:        instance.Spec.LbMgmtNetworkID,
		AmphoraDefaultFlavorID: defaultFlavorID,
		LbSecurityGroupID:      instance.Spec.LbSecurityGroupID,
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

	instance.Status.Conditions.MarkTrue(condition.InputReadyCondition, condition.InputReadyMessage)

	//
	// TLS input validation
	//
	// Validate the CA cert secret if provided
	if instance.Spec.TLS.CaBundleSecretName != "" {
		hash, err := tls.ValidateCACertSecret(
			ctx,
			helper.GetClient(),
			types.NamespacedName{
				Name:      instance.Spec.TLS.CaBundleSecretName,
				Namespace: instance.Namespace,
			},
		)
		if err != nil {
			if k8s_errors.IsNotFound(err) {
				instance.Status.Conditions.Set(condition.FalseCondition(
					condition.TLSInputReadyCondition,
					condition.RequestedReason,
					condition.SeverityInfo,
					fmt.Sprintf(condition.TLSInputReadyWaitingMessage, instance.Spec.TLS.CaBundleSecretName)))
				return ctrl.Result{}, nil
			}
			instance.Status.Conditions.Set(condition.FalseCondition(
				condition.TLSInputReadyCondition,
				condition.ErrorReason,
				condition.SeverityWarning,
				condition.TLSInputErrorMessage,
				err.Error()))
			return ctrl.Result{}, err
		}

		if hash != "" {
			configMapVars[tls.CABundleKey] = env.SetValue(hash)
		}
	}
	// all cert input checks out so report InputReady
	instance.Status.Conditions.MarkTrue(condition.TLSInputReadyCondition, condition.InputReadyMessage)

	//
	// create hash over all the different input resources to identify if any those changed
	// and a restart/recreate is required.
	//
	inputHash, err := r.createHashOfInputHashes(instance, configMapVars)
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
	// normal reconcile tasks
	//

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
			err := fmt.Errorf("not all pods have interfaces with ips as configured in NetworkAttachments: %s", instance.Spec.NetworkAttachments)
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
		Log.Info("Not all conditions are ready for Amphora controller")
	}
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
	db, err := mariadbv1.GetDatabaseByNameAndAccount(ctx, helper, octavia.DatabaseName, instance.Spec.DatabaseAccount, instance.Namespace)
	if err != nil {
		return err
	}
	var tlsCfg *tls.Service
	if instance.Spec.TLS.CaBundleSecretName != "" {
		tlsCfg = &tls.Service{}
	}

	customData := map[string]string{
		common.CustomServiceConfigFileName: instance.Spec.CustomServiceConfig,
		"my.cnf":                           db.GetDatabaseClientConfig(tlsCfg), //(mschuppert) for now just get the default my.cnf
	}
	for key, data := range instance.Spec.DefaultConfigOverwrite {
		customData[key] = data
	}

	databaseAccount, dbSecret, err := mariadbv1.GetAccountAndSecret(
		ctx, helper, instance.Spec.DatabaseAccount, instance.Namespace)

	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			mariadbv1.MariaDBAccountReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			mariadbv1.MariaDBAccountNotReadyMessage,
			err.Error()))

		return err
	}

	persistenceDatabaseAccount, persistenceDbSecret, err := mariadbv1.GetAccountAndSecret(
		ctx, helper, instance.Spec.PersistenceDatabaseAccount, instance.Namespace)

	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			mariadbv1.MariaDBAccountReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			mariadbv1.MariaDBAccountNotReadyMessage,
			err.Error()))

		return err
	}

	instance.Status.Conditions.MarkTrue(
		mariadbv1.MariaDBAccountReadyCondition,
		mariadbv1.MariaDBAccountReadyMessage)

	templateParameters := map[string]interface{}{
		"DatabaseConnection": fmt.Sprintf("mysql+pymysql://%s:%s@%s/%s?read_default_file=/etc/my.cnf",
			databaseAccount.Spec.UserName,
			string(dbSecret.Data[mariadbv1.DatabasePasswordSelector]),
			instance.Spec.DatabaseHostname,
			octavia.DatabaseName,
		),
		"PersistenceDatabaseConnection": fmt.Sprintf("mysql+pymysql://%s:%s@%s/%s?read_default_file=/etc/my.cnf",
			persistenceDatabaseAccount.Spec.UserName,
			string(persistenceDbSecret.Data[mariadbv1.DatabasePasswordSelector]),
			instance.Spec.DatabaseHostname,
			octavia.PersistenceDatabaseName,
		),
	}

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

	parentOctaviaName := octavia.GetOwningOctaviaControllerName(
		instance)
	serverCAPassSecretName := fmt.Sprintf("%s-ca-passphrase", parentOctaviaName)
	caPassSecret, _, err := oko_secret.GetSecret(
		ctx, helper, serverCAPassSecretName, instance.Namespace)
	if err != nil {
		if k8s_errors.IsNotFound(err) {
			instance.Status.Conditions.Set(condition.FalseCondition(
				condition.InputReadyCondition,
				condition.RequestedReason,
				condition.SeverityInfo,
				condition.InputReadyWaitingMessage))
			return fmt.Errorf("OpenStack server CA passphrase secret %s not found",
				serverCAPassSecretName)
		}
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.InputReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			condition.InputReadyErrorMessage,
			err.Error()))
		return err
	}

	//
	// Get the predicatable IPs from the HmConfigMap
	//
	hmMap := &corev1.ConfigMap{}
	err = helper.GetClient().Get(ctx, types.NamespacedName{Name: octavia.HmConfigMap, Namespace: instance.GetNamespace()}, hmMap)
	if err != nil {
		return err
	}
	var ipAddresses []string
	var rsyslogIPAddresses []string
	for key, val := range hmMap.Data {
		if strings.HasPrefix(key, "hm_") {
			ipAddresses = append(ipAddresses, fmt.Sprintf("%s:5555", val))
		}
		if strings.HasPrefix(key, "rsyslog_") {
			// TODO(gthiemonge) Make port configurable
			rsyslogIPAddresses = append(rsyslogIPAddresses, fmt.Sprintf("%s:514", val))
		}
	}
	sort.Strings(ipAddresses)
	sort.Strings(rsyslogIPAddresses)
	ipAddressString := strings.Join(ipAddresses, ",")
	templateParameters["ControllerIPList"] = ipAddressString
	templateParameters["AdminLogTargetList"] = strings.Join(rsyslogIPAddresses, ",")
	templateParameters["TenantLogTargetList"] = strings.Join(rsyslogIPAddresses, ",")

	spec := instance.Spec
	templateParameters["ServiceUser"] = spec.ServiceUser
	templateParameters["KeystoneInternalURL"] = keystoneInternalURL
	templateParameters["KeystonePublicURL"] = keystonePublicURL
	templateParameters["ServiceRoleName"] = spec.Role
	templateParameters["LbMgmtNetworkId"] = templateVars.LbMgmtNetworkID
	templateParameters["LbSecurityGroupId"] = templateVars.LbSecurityGroupID
	templateParameters["AmpFlavorId"] = templateVars.AmphoraDefaultFlavorID
	templateParameters["NovaSshKeyPair"] = octavia.NovaKeyPairName
	templateParameters["AmpImageOwnerId"] = spec.AmphoraImageOwnerID
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

	err = oko_secret.EnsureSecrets(ctx, helper, instance, cms, envVars)
	if err != nil {
		r.Log.Error(err, "unable to process config map")
		return err
	}

	r.Log.Info("Service config map generated")

	return nil
}

func (r *OctaviaAmphoraControllerReconciler) createHashOfInputHashes(
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
		r.Log.Info(fmt.Sprintf("Input maps hash %s - %s", common.InputHashName, hash))
	}
	return hash, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *OctaviaAmphoraControllerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// index passwordSecretField
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &octaviav1.OctaviaAmphoraController{}, passwordSecretField, func(rawObj client.Object) []string {
		// Extract the secret name from the spec, if one is provided
		cr := rawObj.(*octaviav1.OctaviaAmphoraController)
		if cr.Spec.Secret == "" {
			return nil
		}
		return []string{cr.Spec.Secret}
	}); err != nil {
		return err
	}

	// index caBundleSecretNameField
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &octaviav1.OctaviaAmphoraController{}, caBundleSecretNameField, func(rawObj client.Object) []string {
		// Extract the secret name from the spec, if one is provided
		cr := rawObj.(*octaviav1.OctaviaAmphoraController)
		if cr.Spec.TLS.CaBundleSecretName == "" {
			return nil
		}
		return []string{cr.Spec.TLS.CaBundleSecretName}
	}); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&octaviav1.OctaviaAmphoraController{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&appsv1.DaemonSet{}).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findObjectsForSrc),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Complete(r)
}

func (r *OctaviaAmphoraControllerReconciler) findObjectsForSrc(ctx context.Context, src client.Object) []reconcile.Request {
	requests := []reconcile.Request{}

	l := log.FromContext(ctx).WithName("Controllers").WithName("Amphora")

	for _, field := range allWatchFields {
		crList := &octaviav1.OctaviaAmphoraControllerList{}
		listOps := &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(field, src.GetName()),
			Namespace:     src.GetNamespace(),
		}
		err := r.Client.List(ctx, crList, listOps)
		if err != nil {
			return []reconcile.Request{}
		}

		for _, item := range crList.Items {
			l.Info(fmt.Sprintf("input source %s changed, reconcile: %s - %s", src.GetName(), item.GetName(), item.GetNamespace()))

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
