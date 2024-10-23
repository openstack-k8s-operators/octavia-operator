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
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-logr/logr"
	rabbitmqv1 "github.com/openstack-k8s-operators/infra-operator/apis/rabbitmq/v1beta1"
	"github.com/openstack-k8s-operators/lib-common/modules/common"
	"github.com/openstack-k8s-operators/lib-common/modules/common/condition"
	"github.com/openstack-k8s-operators/lib-common/modules/common/deployment"
	"github.com/openstack-k8s-operators/lib-common/modules/common/env"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	"github.com/openstack-k8s-operators/lib-common/modules/common/job"
	"github.com/openstack-k8s-operators/lib-common/modules/common/labels"
	nad "github.com/openstack-k8s-operators/lib-common/modules/common/networkattachment"
	common_rbac "github.com/openstack-k8s-operators/lib-common/modules/common/rbac"
	oko_secret "github.com/openstack-k8s-operators/lib-common/modules/common/secret"
	"github.com/openstack-k8s-operators/lib-common/modules/common/service"
	"github.com/openstack-k8s-operators/lib-common/modules/common/tls"
	"github.com/openstack-k8s-operators/lib-common/modules/common/util"
	mariadbv1 "github.com/openstack-k8s-operators/mariadb-operator/api/v1beta1"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/octavia-operator/pkg/octavia"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// OctaviaReconciler reconciles an Octavia object
type OctaviaReconciler struct {
	client.Client
	Kclient kubernetes.Interface
	Log     logr.Logger
	Scheme  *runtime.Scheme
}

// GetLogger returns a logger object with a prefix of "controller.name" and additional controller context fields
func (r *OctaviaReconciler) GetLogger(ctx context.Context) logr.Logger {
	return log.FromContext(ctx).WithName("Controllers").WithName("Octavia")
}

// +kubebuilder:rbac:groups=octavia.openstack.org,resources=octavias,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=octavia.openstack.org,resources=octavias/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=octavia.openstack.org,resources=octavias/finalizers,verbs=update;patch
// +kubebuilder:rbac:groups=octavia.openstack.org,resources=octaviaapis,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=octavia.openstack.org,resources=octaviaapis/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=octavia.openstack.org,resources=octaviaapis/finalizers,verbs=update;patch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete;
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete;
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete;
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;update;patch;delete;
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete;
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;create;update;patch;delete;
// +kubebuilder:rbac:groups=route.openshift.io,resources=routes,verbs=get;list;watch;create;update;patch;delete;
// +kubebuilder:rbac:groups=mariadb.openstack.org,resources=mariadbdatabases,verbs=get;list;watch;create;update;patch;delete;
// +kubebuilder:rbac:groups=mariadb.openstack.org,resources=mariadbdatabases/finalizers,verbs=update;patch
// +kubebuilder:rbac:groups=mariadb.openstack.org,resources=mariadbaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=mariadb.openstack.org,resources=mariadbaccounts/finalizers,verbs=update;patch
// +kubebuilder:rbac:groups=keystone.openstack.org,resources=keystoneapis,verbs=get;list;watch;
// +kubebuilder:rbac:groups=keystone.openstack.org,resources=keystoneservices,verbs=get;list;watch;create;update;patch;delete;
// +kubebuilder:rbac:groups=keystone.openstack.org,resources=keystoneendpoints,verbs=get;list;watch;create;update;patch;delete;
// +kubebuilder:rbac:groups=rabbitmq.openstack.org,resources=transporturls,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=k8s.cni.cncf.io,resources=network-attachment-definitions,verbs=get;list;watch

// service account, role, rolebinding
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="rbac.authorization.k8s.io",resources=roles,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="rbac.authorization.k8s.io",resources=rolebindings,verbs=get;list;watch;create;update;patch
// service account permissions that are needed to grant permission to the above
// +kubebuilder:rbac:groups="security.openshift.io",resourceNames=anyuid;privileged,resources=securitycontextconstraints,verbs=use
// +kubebuilder:rbac:groups="",resources=pods,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Octavia object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *OctaviaReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, _err error) {
	Log := r.GetLogger(ctx)

	// Fetch the Octavia instance
	instance := &octaviav1.Octavia{}
	err := r.Client.Get(ctx, req.NamespacedName, instance)
	if err != nil {
		if k8s_errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected.
			// For additional cleanup logic use finalizers. Return and don't requeue.
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

	//
	// initialize status
	//

	cl := condition.CreateList(
		condition.UnknownCondition(condition.ReadyCondition, condition.InitReason, condition.ReadyInitMessage),
		condition.UnknownCondition(condition.DBReadyCondition, condition.InitReason, condition.DBReadyInitMessage),
		condition.UnknownCondition(condition.DBSyncReadyCondition, condition.InitReason, condition.DBSyncReadyInitMessage),
		condition.UnknownCondition(condition.RabbitMqTransportURLReadyCondition, condition.InitReason, condition.RabbitMqTransportURLReadyInitMessage),
		condition.UnknownCondition(condition.InputReadyCondition, condition.InitReason, condition.InputReadyInitMessage),
		condition.UnknownCondition(condition.ServiceConfigReadyCondition, condition.InitReason, condition.ServiceConfigReadyInitMessage),
		condition.UnknownCondition(condition.ServiceAccountReadyCondition, condition.InitReason, condition.ServiceAccountReadyInitMessage),
		condition.UnknownCondition(condition.RoleReadyCondition, condition.InitReason, condition.RoleReadyInitMessage),
		condition.UnknownCondition(condition.RoleBindingReadyCondition, condition.InitReason, condition.RoleBindingReadyInitMessage),
		condition.UnknownCondition(octaviav1.OctaviaAPIReadyCondition, condition.InitReason, octaviav1.OctaviaAPIReadyInitMessage),
		condition.UnknownCondition(condition.NetworkAttachmentsReadyCondition, condition.InitReason, condition.NetworkAttachmentsReadyInitMessage),
		condition.UnknownCondition(condition.ExposeServiceReadyCondition, condition.InitReason, condition.ExposeServiceReadyInitMessage),
		condition.UnknownCondition(octaviav1.OctaviaAmphoraCertsReadyCondition, condition.InitReason, octaviav1.OctaviaAmphoraCertsReadyInitMessage),
		condition.UnknownCondition(octaviav1.OctaviaQuotasReadyCondition, condition.InitReason, octaviav1.OctaviaQuotasReadyInitMessage),
		condition.UnknownCondition(octaviav1.OctaviaAmphoraSSHReadyCondition, condition.InitReason, octaviav1.OctaviaAmphoraSSHReadyInitMessage),
		condition.UnknownCondition(octaviav1.OctaviaAmphoraImagesReadyCondition, condition.InitReason, octaviav1.OctaviaAmphoraImagesReadyInitMessage),
		condition.UnknownCondition(octaviav1.OctaviaManagementNetworkReadyCondition, condition.InitReason, octaviav1.OctaviaManagementNetworkReadyInitMessage),
		amphoraControllerInitCondition(octaviav1.HealthManager),
		amphoraControllerInitCondition(octaviav1.Housekeeping),
		amphoraControllerInitCondition(octaviav1.Worker),
	)

	instance.Status.Conditions.Init(&cl)
	instance.Status.ObservedGeneration = instance.Generation

	// If we're not deleting this and the service object doesn't have our finalizer, add it.
	if instance.DeletionTimestamp.IsZero() && controllerutil.AddFinalizer(instance, helper.GetFinalizer()) || isNewInstance {
		return ctrl.Result{}, nil
	}

	if instance.Status.Hash == nil {
		instance.Status.Hash = map[string]string{}
	}

	// Handle service delete
	if !instance.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, instance, helper)
	}

	// Handle non-deleted clusters
	return r.reconcileNormal(ctx, instance, helper)
}

// fields to index to reconcile when change
const (
	passwordSecretField     = ".spec.secret"
	caBundleSecretNameField = ".spec.tls.caBundleSecretName"
	tlsAPIInternalField     = ".spec.tls.api.internal.secretName"
	tlsAPIPublicField       = ".spec.tls.api.public.secretName"
	tlsOvnField             = ".spec.tls.ovn.secretName"
)

var (
	allWatchFields = []string{
		passwordSecretField,
		caBundleSecretNameField,
		tlsAPIInternalField,
		tlsAPIPublicField,
		tlsOvnField,
	}
)

// SetupWithManager sets up the controller with the Manager.
func (r *OctaviaReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&octaviav1.Octavia{}).
		Owns(&mariadbv1.MariaDBDatabase{}).
		Owns(&mariadbv1.MariaDBAccount{}).
		Owns(&octaviav1.OctaviaAPI{}).
		Owns(&octaviav1.OctaviaAmphoraController{}).
		Owns(&batchv1.Job{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&rbacv1.Role{}).
		Owns(&rbacv1.RoleBinding{}).
		Owns(&corev1.Service{}).
		Owns(&rabbitmqv1.TransportURL{}).
		Complete(r)
}

func (r *OctaviaReconciler) reconcileDelete(ctx context.Context, instance *octaviav1.Octavia, helper *helper.Helper) (ctrl.Result, error) {
	Log := r.GetLogger(ctx)
	util.LogForObject(helper, "Reconciling Service delete", instance)

	// remove db finalizer first
	octaviaDb, err := mariadbv1.GetDatabaseByNameAndAccount(ctx, helper, octavia.DatabaseCRName, instance.Spec.DatabaseAccount, instance.Namespace)
	if err != nil && !k8s_errors.IsNotFound(err) {
		return ctrl.Result{}, err
	}

	if !k8s_errors.IsNotFound(err) {
		if err := octaviaDb.DeleteFinalizer(ctx, helper); err != nil {
			return ctrl.Result{}, err
		}
	}

	persistenceDb, err := mariadbv1.GetDatabaseByNameAndAccount(ctx, helper, octavia.PersistenceDatabaseCRName, instance.Spec.PersistenceDatabaseAccount, instance.Namespace)
	if err != nil && !k8s_errors.IsNotFound(err) {
		return ctrl.Result{}, err
	}

	if !k8s_errors.IsNotFound(err) {
		if err := persistenceDb.DeleteFinalizer(ctx, helper); err != nil {
			return ctrl.Result{}, err
		}
	}

	// We did all the cleanup on the objects we created so we can remove the
	// finalizer from ourselves to allow the deletion
	controllerutil.RemoveFinalizer(instance, helper.GetFinalizer())
	Log.Info(fmt.Sprintf("Reconciled Service '%s' delete successfully", instance.Name))

	util.LogForObject(helper, "Reconciled Service delete successfully", instance)
	return ctrl.Result{}, nil
}

func (r *OctaviaReconciler) reconcileInit(
	ctx context.Context,
	instance *octaviav1.Octavia,
	helper *helper.Helper,
	serviceLabels map[string]string,
	serviceAnnotations map[string]string,
) (ctrl.Result, error) {
	Log := r.GetLogger(ctx)
	Log.Info("Reconciling Service init")

	// Secrets
	secretsVars := make(map[string]env.Setter)

	//
	// check for required OpenStack secret holding passwords for service/admin user and add hash to the vars map
	//
	ospSecretHash, result, err := oko_secret.VerifySecret(
		ctx,
		types.NamespacedName{Namespace: instance.Namespace, Name: instance.Spec.Secret},
		[]string{instance.Spec.PasswordSelectors.Service},
		helper.GetClient(),
		time.Duration(10)*time.Second,
	)

	if err != nil {
		if k8s_errors.IsNotFound(err) {
			Log.Info(fmt.Sprintf("OpenStack secret %s not found", instance.Spec.Secret))
			instance.Status.Conditions.Set(condition.FalseCondition(
				condition.InputReadyCondition,
				condition.RequestedReason,
				condition.SeverityInfo,
				condition.InputReadyWaitingMessage))
			return ctrl.Result{RequeueAfter: time.Second * 10}, nil
		}
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.InputReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			condition.InputReadyErrorMessage,
			err.Error()))
		return ctrl.Result{}, err
	} else if (result != ctrl.Result{}) {
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.InputReadyCondition,
			condition.RequestedReason,
			condition.SeverityInfo,
			condition.InputReadyWaitingMessage))
		return result, err
	}
	secretsVars[instance.Spec.Secret] = env.SetValue(ospSecretHash)

	transportURLSecretHash, result, err := oko_secret.VerifySecret(
		ctx,
		types.NamespacedName{Namespace: instance.Namespace, Name: instance.Status.TransportURLSecret},
		[]string{"transport_url"},
		helper.GetClient(),
		time.Duration(10)*time.Second,
	)
	if err != nil {
		if k8s_errors.IsNotFound(err) {
			Log.Info(fmt.Sprintf("TransportURL secret %s not found", instance.Status.TransportURLSecret))
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
	} else if (result != ctrl.Result{}) {
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.InputReadyCondition,
			condition.RequestedReason,
			condition.SeverityInfo,
			condition.InputReadyWaitingMessage))
		return result, err
	}
	secretsVars[instance.Status.TransportURLSecret] = env.SetValue(transportURLSecretHash)

	octaviaDb, persistenceDb, result, err := r.ensureDB(ctx, helper, instance)
	if err != nil {
		return ctrl.Result{}, err
	} else if (result != ctrl.Result{}) {
		return result, nil
	}

	//
	// create Secrets required for octavia input
	// - %-scripts secret holding scripts to e.g. bootstrap the service
	// - %-config secret holding minimal octavia config required to get the service up, user can add additional files to be added to the service
	//
	err = r.generateServiceSecrets(ctx, instance, helper, &secretsVars, octaviaDb, persistenceDb)
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
	_, hashChanged, err := r.createHashOfInputHashes(ctx, instance, secretsVars)
	if err != nil {
		return ctrl.Result{}, err
	} else if hashChanged {
		// Hash changed and instance status should be updated (which will be done by main defer func),
		// so we need to return and reconcile again
		return ctrl.Result{}, nil
	}
	// Create Secrets - end

	instance.Status.Conditions.MarkTrue(condition.ServiceConfigReadyCondition, condition.ServiceConfigReadyMessage)

	//
	// run octavia db sync
	//
	dbSyncHash := instance.Status.Hash[octaviav1.DbSyncHash]
	jobDef := octavia.DbSyncJob(instance, serviceLabels, serviceAnnotations)
	Log.Info("Initializing db sync job")
	dbSyncjob := job.NewJob(
		jobDef,
		octaviav1.DbSyncHash,
		instance.Spec.PreserveJobs,
		time.Duration(5)*time.Second,
		dbSyncHash,
	)
	ctrlResult, err := dbSyncjob.DoJob(
		ctx,
		helper,
	)
	if (ctrlResult != ctrl.Result{}) {
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.DBSyncReadyCondition,
			condition.RequestedReason,
			condition.SeverityInfo,
			condition.DBSyncReadyRunningMessage))
		return ctrlResult, nil
	}
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.DBSyncReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			condition.DBSyncReadyErrorMessage,
			err.Error()))
		return ctrl.Result{}, err
	}
	if dbSyncjob.HasChanged() {
		instance.Status.Hash[octaviav1.DbSyncHash] = dbSyncjob.GetHash()
	}
	instance.Status.Conditions.MarkTrue(condition.DBSyncReadyCondition, condition.DBSyncReadyMessage)

	// run octavia db sync - end

	Log.Info("Reconciled Service init successfully")
	return ctrl.Result{}, nil
}

func (r *OctaviaReconciler) reconcileUpdate(ctx context.Context) (ctrl.Result, error) {
	Log := r.GetLogger(ctx)
	Log.Info("Reconciling Service update")

	// TODO: should have minor update tasks if required
	// - delete dbsync hash from status to rerun it?

	Log.Info("Reconciled Service update successfully")
	return ctrl.Result{}, nil
}

func (r *OctaviaReconciler) reconcileUpgrade(ctx context.Context) (ctrl.Result, error) {
	Log := r.GetLogger(ctx)
	Log.Info("Reconciling Service upgrade")

	// TODO: should have major version upgrade tasks
	// -delete dbsync hash from status to rerun it?

	Log.Info("Reconciled Service upgrade successfully")
	return ctrl.Result{}, nil
}

func (r *OctaviaReconciler) reconcileNormal(ctx context.Context, instance *octaviav1.Octavia, helper *helper.Helper) (ctrl.Result, error) {
	Log := r.GetLogger(ctx)
	Log.Info("Reconciling Service")

	// Service account, role, binding
	rbacRules := []rbacv1.PolicyRule{
		{
			APIGroups:     []string{"security.openshift.io"},
			ResourceNames: []string{"anyuid", "privileged"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"create", "get", "list", "watch", "update", "patch", "delete"},
		},
	}
	rbacResult, err := common_rbac.ReconcileRbac(ctx, helper, instance, rbacRules)
	if err != nil {
		return rbacResult, err
	} else if (rbacResult != ctrl.Result{}) {
		return rbacResult, nil
	}

	transportURL, op, err := r.transportURLCreateOrUpdate(instance)
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.RabbitMqTransportURLReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			condition.RabbitMqTransportURLReadyErrorMessage, err.Error()))
		return ctrl.Result{}, err
	}

	if op != controllerutil.OperationResultNone {
		Log.Info(fmt.Sprintf("TransportURL %s successfully reconciled - operation: %s", transportURL.Name, string(op)))
	}

	instance.Status.TransportURLSecret = transportURL.Status.SecretName

	if instance.Status.TransportURLSecret == "" {
		Log.Info(fmt.Sprintf("Waiting for the TransportURL %s secret to be created", transportURL.Name))
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.InputReadyCondition,
			condition.RequestedReason,
			condition.SeverityInfo,
			condition.InputReadyWaitingMessage))
		return ctrl.Result{RequeueAfter: time.Duration(10) * time.Second}, nil
	}
	instance.Status.Conditions.MarkTrue(
		condition.RabbitMqTransportURLReadyCondition,
		condition.RabbitMqTransportURLReadyMessage)
	instance.Status.Conditions.MarkTrue(condition.InputReadyCondition, condition.InputReadyMessage)

	err = octavia.EnsureAmphoraCerts(ctx, instance, helper)
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			octaviav1.OctaviaAmphoraCertsReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			octaviav1.OctaviaAmphoraCertsReadyErrorMessage,
			err.Error()))
		return ctrl.Result{}, err
	}
	instance.Status.Conditions.MarkTrue(
		octaviav1.OctaviaAmphoraCertsReadyCondition,
		octaviav1.OctaviaAmphoraCertsReadyCompleteMessage)

	if err = octavia.EnsureQuotas(ctx, instance, &r.Log, helper); err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			octaviav1.OctaviaQuotasReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			octaviav1.OctaviaQuotasReadyErrorMessage,
			err.Error()))
		return ctrl.Result{}, err
	}
	instance.Status.Conditions.MarkTrue(
		octaviav1.OctaviaQuotasReadyCondition,
		octaviav1.OctaviaQuotasReadyCompleteMessage)

	//
	// TODO check when/if Init, Update, or Upgrade should/could be skipped
	//

	serviceLabels := map[string]string{
		common.AppSelector: octavia.ServiceName,
	}

	for _, networkAttachment := range instance.Spec.OctaviaAPI.NetworkAttachments {
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

	serviceAnnotations, err := nad.CreateNetworksAnnotation(instance.Namespace, instance.Spec.OctaviaAPI.NetworkAttachments)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed create network annotation from %s: %w",
			instance.Spec.OctaviaAPI.NetworkAttachments, err)
	}
	instance.Status.Conditions.MarkTrue(condition.NetworkAttachmentsReadyCondition, condition.NetworkAttachmentsReadyMessage)

	// Handle service init
	ctrlResult, err := r.reconcileInit(ctx, instance, helper, serviceLabels, serviceAnnotations)
	if err != nil {
		return ctrlResult, err
	} else if (ctrlResult != ctrl.Result{}) {
		return ctrlResult, nil
	}
	instance.Status.Conditions.MarkTrue(condition.NetworkAttachmentsReadyCondition, condition.NetworkAttachmentsReadyMessage)

	// Handle service update
	ctrlResult, err = r.reconcileUpdate(ctx)
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

	Log.Info(fmt.Sprintf("Calling for deploy for API with %s", instance.Status.DatabaseHostname))

	// TODO(beagles): look into adding condition types/messages in a common file
	octaviaAPI, op, err := r.apiDeploymentCreateOrUpdate(instance)
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			octaviav1.OctaviaAPIReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			octaviav1.OctaviaAPIReadyErrorMessage,
			err.Error()))
		return ctrl.Result{}, err
	}
	// Check the underlying OctaviaAPI condition according to the
	// ObservedGeneration
	apiObsGen, err := r.checkOctaviaAPIGeneration(instance)
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			octaviav1.OctaviaAPIReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			octaviav1.OctaviaAPIReadyErrorMessage,
			err.Error()))
		return ctrlResult, nil
	}
	if !apiObsGen {
		instance.Status.Conditions.Set(condition.UnknownCondition(
			octaviav1.OctaviaAPIReadyCondition,
			condition.InitReason,
			octaviav1.OctaviaAPIReadyInitMessage,
		))
	} else {
		// Mirror OctaviaAPI status' ReadyCount to this parent CR
		instance.Status.OctaviaAPIReadyCount = octaviaAPI.Status.ReadyCount
		conditionStatus := octaviaAPI.Status.Conditions.Mirror(octaviav1.OctaviaAPIReadyCondition)
		if conditionStatus != nil {
			instance.Status.Conditions.Set(conditionStatus)
		}
	}
	if op != controllerutil.OperationResultNone && apiObsGen {
		Log.Info(fmt.Sprintf("Deployment %s successfully reconciled - operation: %s", instance.Name, string(op)))
	}

	// ------------------------------------------------------------------------------------------------------------
	// Amphora reconciliation
	// ------------------------------------------------------------------------------------------------------------

	nad, err := nad.GetNADWithName(ctx, helper, instance.Spec.OctaviaNetworkAttachment, instance.Namespace)
	if err != nil {
		return ctrl.Result{}, err
	}

	networkParameters, err := octavia.GetNetworkParametersFromNAD(nad, instance)
	if err != nil {
		return ctrl.Result{}, err
	}

	var networkInfo octavia.NetworkProvisioningSummary

	if instance.Spec.LbMgmtNetworks.ManageLbMgmtNetworks {
		// Create load balancer management network and get its Id (networkInfo is actually a struct and contains
		// multiple details.
		networkInfo, err = octavia.EnsureAmphoraManagementNetwork(
			ctx,
			instance.Namespace,
			instance.Spec.TenantName,
			&instance.Spec.LbMgmtNetworks,
			networkParameters,
			&Log,
			helper,
		)
		if err != nil {
			instance.Status.Conditions.Set(condition.FalseCondition(
				octaviav1.OctaviaManagementNetworkReadyCondition,
				condition.ErrorReason,
				condition.SeverityWarning,
				octaviav1.OctaviaManagementNetworkReadyErrorMessage,
				err.Error()))
			return ctrl.Result{}, err
		}
	} else {
		networkInfo, err = octavia.HandleUnmanagedAmphoraManagementNetwork(
			ctx,
			instance.Namespace,
			instance.Spec.TenantName,
			&instance.Spec.LbMgmtNetworks,
			&Log,
			helper,
		)
		if err != nil {
			instance.Status.Conditions.Set(condition.FalseCondition(
				octaviav1.OctaviaManagementNetworkReadyCondition,
				condition.ErrorReason,
				condition.SeverityWarning,
				octaviav1.OctaviaManagementNetworkReadyErrorMessage,
				err.Error()))
			return ctrl.Result{}, err
		}
	}
	instance.Status.Conditions.MarkTrue(octaviav1.OctaviaManagementNetworkReadyCondition, octaviav1.OctaviaManagementNetworkReadyCompleteMessage)
	Log.Info(fmt.Sprintf("Using management network \"%s\"", networkInfo.TenantNetworkID))

	ampImageOwnerID, err := octavia.GetImageOwnerID(ctx, instance, helper)
	if err != nil {
		return ctrl.Result{}, err
	}

	nodeConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      octavia.HmConfigMap,
			Namespace: instance.GetNamespace(),
			Labels:    labels.GetLabels(instance, labels.GetGroupLabel(instance.ObjectMeta.Name), map[string]string{}),
		},
		Data: make(map[string]string),
	}

	// Look for existing config map and if exists, read existing data and match
	// against nodes.
	foundMap := &corev1.ConfigMap{}
	err = helper.GetClient().Get(ctx, types.NamespacedName{Name: octavia.HmConfigMap, Namespace: instance.GetNamespace()},
		foundMap)
	if err != nil {
		if k8s_errors.IsNotFound(err) {
			Log.Info(fmt.Sprintf("Port map %s doesn't exist, creating.", octavia.HmConfigMap))
		} else {
			return ctrl.Result{}, err
		}
	} else {
		Log.Info("Retrieved existing map, updating..")
		nodeConfigMap.Data = foundMap.Data
	}

	//
	// Predictable IPs.
	//
	// NOTE(beagles): refactoring this might be nice. This could also  be
	// optimized but the data sets are small (nodes an IP ranges are less than
	// 100) so optimization might be a waste.
	//
	predictableIPParams, err := octavia.GetPredictableIPAM(networkParameters)
	if err != nil {
		return ctrl.Result{}, err
	}
	// Get a list of the nodes in the cluster

	// TODO(beagles):
	// * confirm whether or not this lists only the nodes we want (i.e. ones
	// that will host the daemonset)
	// * do we want to provide a mechanism to temporarily disabling this list
	// for maintenance windows where nodes might be "coming and going"

	nodes, err := helper.GetKClient().CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return ctrl.Result{}, err
	}
	updatedMap := make(map[string]string)
	allocatedIPs := make(map[string]bool)
	var predictableIPsRequired []string

	// First scan existing allocations so we can keep existing allocations.
	// Keeping track of what's required and what already exists. If a node is
	// removed from the cluster, it's IPs will not be added to the allocated
	// list and are effectively recycled.
	for _, node := range nodes.Items {
		Log.Info(fmt.Sprintf("cluster node name %s", node.Name))
		portName := fmt.Sprintf("hm_%s", node.Name)
		if ipValue, ok := nodeConfigMap.Data[portName]; ok {
			updatedMap[portName] = ipValue
			allocatedIPs[ipValue] = true
			Log.Info(fmt.Sprintf("%s has IP mapping %s: %s", node.Name, portName, ipValue))
		} else {
			predictableIPsRequired = append(predictableIPsRequired, portName)
		}
		portName = fmt.Sprintf("rsyslog_%s", node.Name)
		if ipValue, ok := nodeConfigMap.Data[portName]; ok {
			updatedMap[portName] = ipValue
			allocatedIPs[ipValue] = true
			Log.Info(fmt.Sprintf("%s has IP mapping %s: %s", node.Name, portName, ipValue))
		} else {
			predictableIPsRequired = append(predictableIPsRequired, portName)
		}
	}
	// Get new IPs using the range from predictableIPParmas minus the
	// allocatedIPs captured above.
	Log.Info(fmt.Sprintf("Allocating %d predictable IPs", len(predictableIPsRequired)))
	for _, portName := range predictableIPsRequired {
		hmPort, err := octavia.GetNextIP(predictableIPParams, allocatedIPs)
		if err != nil {
			// An error here is really unexpected- it means either we have
			// messed up the allocatedIPs list or the range we are assuming is
			// too small for the number of health managers and rsyslog
			// containers.
			return ctrl.Result{}, err
		}
		updatedMap[portName] = hmPort
	}

	mapLabels := labels.GetLabels(instance, labels.GetGroupLabel(instance.ObjectMeta.Name), map[string]string{})
	_, err = controllerutil.CreateOrPatch(ctx, helper.GetClient(), nodeConfigMap, func() error {
		nodeConfigMap.Labels = util.MergeStringMaps(nodeConfigMap.Labels, mapLabels)
		nodeConfigMap.Data = updatedMap
		err := controllerutil.SetControllerReference(instance, nodeConfigMap, helper.GetScheme())
		if err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		Log.Info("Unable to create config map for health manager ports...")
		return ctrl.Result{}, err
	}

	octaviaHealthManager, op, err := r.amphoraControllerDaemonSetCreateOrUpdate(instance, networkInfo,
		ampImageOwnerID, instance.Spec.OctaviaHealthManager, octaviav1.HealthManager)
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			amphoraControllerReadyCondition(octaviav1.HealthManager),
			condition.ErrorReason,
			condition.SeverityWarning,
			amphoraControllerErrorMessage(octaviav1.HealthManager),
			err.Error()))
		return ctrl.Result{}, err
	}
	// Even if we trigger three deployments, the Amphora subCR is only one, no
	// need to call this functions three times in the same reconciliation loop
	ampObsGen, err := r.checkAmphoraGeneration(instance)
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			amphoraControllerReadyCondition(octaviav1.HealthManager),
			condition.ErrorReason,
			condition.SeverityWarning,
			amphoraControllerErrorMessage(octaviav1.HealthManager),
			err.Error()))
		return ctrlResult, nil
	}
	if !ampObsGen {
		instance.Status.Conditions.Set(condition.UnknownCondition(
			amphoraControllerReadyCondition(octaviav1.HealthManager),
			condition.InitReason,
			amphoraControllerErrorMessage(octaviav1.HealthManager),
		))
	} else {
		instance.Status.OctaviaHealthManagerReadyCount = octaviaHealthManager.Status.ReadyCount
		conditionStatus := octaviaHealthManager.Status.Conditions.Mirror(amphoraControllerReadyCondition(octaviav1.HealthManager))
		if conditionStatus != nil {
			instance.Status.Conditions.Set(conditionStatus)
		}
	}

	if op != controllerutil.OperationResultNone && ampObsGen {
		Log.Info(fmt.Sprintf("Deployment of OctaviaHealthManager for %s successfully reconciled - operation: %s", instance.Name, string(op)))
	}

	//
	// We do not try and reconcile the other controller PODs until after the health manager Pods are all deployed.
	//
	if octaviaHealthManager.Status.ReadyCount != octaviaHealthManager.Status.DesiredNumberScheduled {
		Log.Info("Health managers are not ready. Housekeeping and Worker services pending")
		return ctrl.Result{}, nil
	}

	octaviaRsyslog, op, err := r.octaviaRsyslogDaemonSetCreateOrUpdate(instance, instance.Spec.OctaviaRsyslog)
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			amphoraControllerReadyCondition(octaviav1.Worker),
			condition.ErrorReason,
			condition.SeverityWarning,
			amphoraControllerErrorMessage(octaviav1.Worker),
			err.Error()))
		return ctrl.Result{}, err
	}
	if !ampObsGen {
		instance.Status.Conditions.Set(condition.UnknownCondition(
			amphoraControllerReadyCondition(octaviav1.Worker),
			condition.InitReason,
			amphoraControllerErrorMessage(octaviav1.Worker),
		))
	} else {
		instance.Status.OctaviaRsyslogReadyCount = octaviaRsyslog.Status.ReadyCount
		conditionStatus := octaviaRsyslog.Status.Conditions.Mirror(octaviav1.OctaviaRsyslogReadyCondition)
		if conditionStatus != nil {
			instance.Status.Conditions.Set(conditionStatus)
		}
	}
	if op != controllerutil.OperationResultNone && ampObsGen {
		Log.Info(fmt.Sprintf("Deployment of OctaviaRsyslog for %s successfully reconciled - operation: %s", instance.Name, string(op)))
	}

	// Skip the other amphora controller pods until the health managers are all up and running.
	octaviaHousekeeping, op, err := r.amphoraControllerDaemonSetCreateOrUpdate(instance, networkInfo,
		ampImageOwnerID, instance.Spec.OctaviaHousekeeping, octaviav1.Housekeeping)
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			amphoraControllerReadyCondition(octaviav1.Housekeeping),
			condition.ErrorReason,
			condition.SeverityWarning,
			amphoraControllerErrorMessage(octaviav1.Housekeeping),
			err.Error()))
		return ctrl.Result{}, err
	}
	if !ampObsGen {
		instance.Status.Conditions.Set(condition.UnknownCondition(
			amphoraControllerReadyCondition(octaviav1.Housekeeping),
			condition.InitReason,
			amphoraControllerErrorMessage(octaviav1.Housekeeping),
		))
	} else {
		instance.Status.OctaviaHousekeepingReadyCount = octaviaHousekeeping.Status.ReadyCount
		conditionStatus := octaviaHousekeeping.Status.Conditions.Mirror(amphoraControllerReadyCondition(octaviav1.Housekeeping))
		if conditionStatus != nil {
			instance.Status.Conditions.Set(conditionStatus)
		}
	}

	if op != controllerutil.OperationResultNone && ampObsGen {
		Log.Info(fmt.Sprintf("Deployment of OctaviaHousekeeping for %s successfully reconciled - operation: %s", instance.Name, string(op)))
	}

	octaviaWorker, op, err := r.amphoraControllerDaemonSetCreateOrUpdate(instance, networkInfo,
		ampImageOwnerID, instance.Spec.OctaviaWorker, octaviav1.Worker)
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			amphoraControllerReadyCondition(octaviav1.Worker),
			condition.ErrorReason,
			condition.SeverityWarning,
			amphoraControllerErrorMessage(octaviav1.Worker),
			err.Error()))
		return ctrl.Result{}, err
	}
	if !ampObsGen {
		instance.Status.Conditions.Set(condition.UnknownCondition(
			amphoraControllerReadyCondition(octaviav1.Worker),
			condition.InitReason,
			amphoraControllerErrorMessage(octaviav1.Worker),
		))
	} else {
		instance.Status.OctaviaWorkerReadyCount = octaviaWorker.Status.ReadyCount
		conditionStatus := octaviaWorker.Status.Conditions.Mirror(amphoraControllerReadyCondition(octaviav1.Worker))
		if conditionStatus != nil {
			instance.Status.Conditions.Set(conditionStatus)
		}
	}
	if op != controllerutil.OperationResultNone && ampObsGen {
		Log.Info(fmt.Sprintf("Deployment of OctaviaWorker for %s successfully reconciled - operation: %s", instance.Name, string(op)))
	}

	// remove finalizers from unused MariaDBAccount records
	err = mariadbv1.DeleteUnusedMariaDBAccountFinalizers(ctx, helper, octavia.DatabaseCRName, instance.Spec.DatabaseAccount, instance.Namespace)
	if err != nil {
		return ctrl.Result{}, err
	}

	err = mariadbv1.DeleteUnusedMariaDBAccountFinalizers(ctx, helper, octavia.PersistenceDatabaseCRName, instance.Spec.PersistenceDatabaseAccount, instance.Namespace)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Amphora SSH key config for debugging
	err = octavia.EnsureAmpSSHConfig(ctx, instance, helper)
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			octaviav1.OctaviaAmphoraSSHReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			octaviav1.OctaviaAmphoraSSHReadyErrorMessage,
			err.Error()))
		return ctrl.Result{}, err
	}
	instance.Status.Conditions.MarkTrue(
		octaviav1.OctaviaAmphoraSSHReadyCondition,
		octaviav1.OctaviaAmphoraSSHReadyCompleteMessage)

	ctrlResult, err = r.reconcileAmphoraImages(ctx, instance, helper)
	if (ctrlResult != ctrl.Result{}) {
		return ctrlResult, nil
	}
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			octaviav1.OctaviaAmphoraImagesReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			octaviav1.OctaviaAmphoraImagesReadyErrorMessage,
			err.Error()))
		return ctrl.Result{}, err
	}
	instance.Status.Conditions.MarkTrue(
		octaviav1.OctaviaAmphoraImagesReadyCondition,
		octaviav1.OctaviaAmphoraImagesReadyCompleteMessage)

	instance.Status.Conditions.MarkTrue(condition.ExposeServiceReadyCondition, condition.ExposeServiceReadyMessage)

	// create Deployment - end

	// We reached the end of the Reconcile, update the Ready condition based on
	// the sub conditions
	if instance.Status.Conditions.AllSubConditionIsTrue() {
		instance.Status.Conditions.MarkTrue(
			condition.ReadyCondition, condition.ReadyMessage)
	}
	Log.Info("Reconciled Service successfully")
	return ctrl.Result{}, nil
}

// ensureDB - set up the main database and the "persistence" database.
// this then drives the ability to generate the config
func (r *OctaviaReconciler) ensureDB(
	ctx context.Context,
	h *helper.Helper,
	instance *octaviav1.Octavia,
) (*mariadbv1.Database, *mariadbv1.Database, ctrl.Result, error) {

	// ensure MariaDBAccount exists.  This account record may be created by
	// openstack-operator or the cloud operator up front without a specific
	// MariaDBDatabase configured yet.   Otherwise, a MariaDBAccount CR is
	// created here with a generated username as well as a secret with
	// generated password.   The MariaDBAccount is created without being
	// yet associated with any MariaDBDatabase.

	_, _, err := mariadbv1.EnsureMariaDBAccount(
		ctx, h, instance.Spec.DatabaseAccount,
		instance.Namespace, false, octavia.DatabaseUsernamePrefix,
	)

	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			mariadbv1.MariaDBAccountReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			mariadbv1.MariaDBAccountNotReadyMessage,
			err.Error()))

		return nil, nil, ctrl.Result{}, err
	}

	_, _, err = mariadbv1.EnsureMariaDBAccount(
		ctx, h, instance.Spec.PersistenceDatabaseAccount,
		instance.Namespace, false, octavia.DatabaseUsernamePrefix,
	)

	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			mariadbv1.MariaDBAccountReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			mariadbv1.MariaDBAccountNotReadyMessage,
			err.Error()))

		return nil, nil, ctrl.Result{}, err
	}
	instance.Status.Conditions.MarkTrue(
		mariadbv1.MariaDBAccountReadyCondition,
		mariadbv1.MariaDBAccountReadyMessage)

	//
	// create service DB instance
	//
	octaviaDb := mariadbv1.NewDatabaseForAccount(
		instance.Spec.DatabaseInstance, // mariadb/galera service to target
		octavia.DatabaseName,           // name used in CREATE DATABASE in mariadb
		octavia.DatabaseCRName,         // CR name for MariaDBDatabase
		instance.Spec.DatabaseAccount,  // CR name for MariaDBAccount
		instance.Namespace,             // namespace
	)

	persistenceDb := mariadbv1.NewDatabaseForAccount(
		instance.Spec.DatabaseInstance,           // mariadb/galera service to target
		octavia.PersistenceDatabaseName,          // name used in CREATE DATABASE in mariadb
		octavia.PersistenceDatabaseCRName,        // CR name for MariaDBDatabase
		instance.Spec.PersistenceDatabaseAccount, // CR name for MariaDBAccount
		instance.Namespace,                       // namespace
	)

	dbs := []*mariadbv1.Database{octaviaDb, persistenceDb}

	for _, db := range dbs {
		// create or patch the DB
		ctrlResult, err := db.CreateOrPatchAll(ctx, h)

		if err != nil {
			instance.Status.Conditions.Set(condition.FalseCondition(
				condition.DBReadyCondition,
				condition.ErrorReason,
				condition.SeverityWarning,
				condition.DBReadyErrorMessage,
				err.Error()))
			return octaviaDb, persistenceDb, ctrl.Result{}, err
		}
		if (ctrlResult != ctrl.Result{}) {
			instance.Status.Conditions.Set(condition.FalseCondition(
				condition.DBReadyCondition,
				condition.RequestedReason,
				condition.SeverityInfo,
				condition.DBReadyRunningMessage))
			return octaviaDb, persistenceDb, ctrlResult, nil
		}

		// wait for the DB to be setup
		ctrlResult, err = db.WaitForDBCreated(ctx, h)
		if err != nil {
			instance.Status.Conditions.Set(condition.FalseCondition(
				condition.DBReadyCondition,
				condition.ErrorReason,
				condition.SeverityWarning,
				condition.DBReadyErrorMessage,
				err.Error()))
			return octaviaDb, persistenceDb, ctrlResult, err
		}
		if (ctrlResult != ctrl.Result{}) {
			instance.Status.Conditions.Set(condition.FalseCondition(
				condition.DBReadyCondition,
				condition.RequestedReason,
				condition.SeverityInfo,
				condition.DBReadyRunningMessage))
			return octaviaDb, persistenceDb, ctrlResult, nil
		}
	}

	// update Status.DatabaseHostname, used to bootstrap/config the service
	instance.Status.DatabaseHostname = dbs[0].GetDatabaseHostname()
	instance.Status.Conditions.MarkTrue(condition.DBReadyCondition, condition.DBReadyMessage)

	return octaviaDb, persistenceDb, ctrl.Result{}, nil

	// create service DB - end
}

func (r *OctaviaReconciler) reconcileAmphoraImages(
	ctx context.Context,
	instance *octaviav1.Octavia,
	helper *helper.Helper,
) (ctrl.Result, error) {
	Log := r.GetLogger(ctx)

	var ctrlResult ctrl.Result
	if instance.Spec.AmphoraImageContainerImage == "" {
		if instance.Status.Hash[octaviav1.ImageUploadHash] != "" {
			Log.Info("Reseting image upload hash")
			instance.Status.Hash[octaviav1.ImageUploadHash] = ""
		}
		return ctrl.Result{}, nil
	}

	hash, err := util.ObjectHash(instance.Spec.AmphoraImageContainerImage)
	if err != nil {
		return ctrl.Result{}, err
	}
	if hash == instance.Status.Hash[octaviav1.ImageUploadHash] {
		// No change
		return ctrl.Result{}, nil
	}

	serviceLabels := map[string]string{
		common.AppSelector: octavia.ServiceName + "-image",
	}

	exportLabels := util.MergeStringMaps(
		serviceLabels,
		map[string]string{
			service.AnnotationEndpointKey: "internal",
		},
	)

	svc, err := service.NewService(
		service.GenericService(&service.GenericServiceDetails{
			Name:      "octavia-image-upload-internal",
			Namespace: instance.Namespace,
			Labels:    exportLabels,
			Selector:  serviceLabels,
			Ports: []corev1.ServicePort{
				{
					Name:       "octavia-image-upload-internal",
					Port:       octavia.ApacheInternalPort,
					TargetPort: intstr.FromInt(8080),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		}),
		5,
		nil,
	)
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.ExposeServiceReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			condition.ExposeServiceReadyErrorMessage,
			err.Error()))

		return ctrl.Result{}, err
	}
	svc.AddAnnotation(map[string]string{
		service.AnnotationEndpointKey: "internal",
	})
	svc.AddAnnotation(map[string]string{
		service.AnnotationIngressCreateKey: "false",
	})

	ctrlResult, err = svc.CreateOrPatch(ctx, helper)
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.ExposeServiceReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			condition.ExposeServiceReadyErrorMessage,
			err.Error()))

		return ctrlResult, err
	} else if (ctrlResult != ctrl.Result{}) {
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.ExposeServiceReadyCondition,
			condition.RequestedReason,
			condition.SeverityInfo,
			condition.ExposeServiceReadyRunningMessage))
		return ctrlResult, nil
	}
	Log.Info("Initializing amphora image upload deployment")
	depl := deployment.NewDeployment(
		octavia.ImageUploadDeployment(instance, serviceLabels),
		time.Duration(5)*time.Second,
	)
	ctrlResult, err = depl.CreateOrPatch(ctx, helper)
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			octaviav1.OctaviaAmphoraImagesReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			octaviav1.OctaviaAmphoraImagesReadyErrorMessage,
			err.Error()))
		return ctrlResult, err
	} else if (ctrlResult != ctrl.Result{}) {
		instance.Status.Conditions.Set(condition.FalseCondition(
			octaviav1.OctaviaAmphoraImagesReadyCondition,
			condition.RequestedReason,
			condition.SeverityInfo,
			octaviav1.OctaviaAmphoraImagesReadyRunningMessage))
		return ctrlResult, nil
	}
	readyCount := depl.GetDeployment().Status.ReadyReplicas
	if readyCount == 0 {
		// Not ready, wait for the next loop
		Log.Info("Image Upload Pod not ready")
		return ctrl.Result{Requeue: true, RequeueAfter: 1 * time.Second}, nil
	}
	endpoint, err := svc.GetAPIEndpoint(nil, nil, "")
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			octaviav1.OctaviaAmphoraImagesReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			octaviav1.OctaviaAmphoraImagesReadyErrorMessage,
			err.Error()))
		return ctrl.Result{}, err
	}

	urlMap, err := r.getLocalImageURLs(endpoint)
	if err != nil {
		Log.Info(fmt.Sprintf("Cannot get amphora image list: %s", err))
		instance.Status.Conditions.Set(condition.FalseCondition(
			octaviav1.OctaviaAmphoraImagesReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			octaviav1.OctaviaAmphoraImagesReadyErrorMessage,
			err.Error()))
		return ctrl.Result{}, err
	}

	ok, err := octavia.EnsureAmphoraImages(ctx, instance, &r.Log, helper, urlMap)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !ok {
		// Images are not ready
		Log.Info("Waiting for amphora images to be ready")
		instance.Status.Conditions.Set(condition.FalseCondition(
			octaviav1.OctaviaAmphoraImagesReadyCondition,
			condition.RequestedReason,
			condition.SeverityInfo,
			octaviav1.OctaviaAmphoraImagesReadyRunningMessage))
		return ctrl.Result{Requeue: true, RequeueAfter: 5 * time.Second}, nil
	}
	Log.Info(fmt.Sprintf("Setting image upload hash - %s", hash))
	instance.Status.Hash[octaviav1.ImageUploadHash] = hash

	// Tasks are successful, the deployment can be deleted
	Log.Info("Deleting amphora image upload deployment")
	err = depl.Delete(ctx, helper)
	if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *OctaviaReconciler) getLocalImageURLs(
	endpoint string,
) ([]octavia.AmphoraImage, error) {
	// Get the list of images and their hashes
	listURL := fmt.Sprintf("%s/octavia-amphora-image.sha256sum", endpoint)

	resp, err := http.Get(listURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	scanner := bufio.NewScanner(resp.Body)
	ret := []octavia.AmphoraImage{}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 {
			name, _ := strings.CutSuffix(fields[1], ".qcow2")
			ret = append(ret, octavia.AmphoraImage{
				Name:     name,
				URL:      fmt.Sprintf("%s/%s", endpoint, fields[1]),
				Checksum: fields[0],
			})
		}
	}

	return ret, nil
}

// generateServiceSecrets - create secrets which hold scripts and service configuration
// TODO add DefaultConfigOverwrite
func (r *OctaviaReconciler) generateServiceSecrets(
	ctx context.Context,
	instance *octaviav1.Octavia,
	h *helper.Helper,
	envVars *map[string]env.Setter,
	octaviaDb *mariadbv1.Database,
	persistenceDb *mariadbv1.Database,
) error {
	//
	// create Secret required for octavia input
	// - %-scripts secret holding scripts to e.g. bootstrap the service
	// - %-config secret holding minimal octavia config required to get the service up, user can add additional files to be added to the service
	//

	cmLabels := labels.GetLabels(instance, labels.GetGroupLabel(octavia.ServiceName), map[string]string{})

	var tlsCfg *tls.Service
	if instance.Spec.OctaviaAPI.TLS.Ca.CaBundleSecretName != "" {
		tlsCfg = &tls.Service{}
	}

	// customData hold any customization for the service.
	// custom.conf is going to /etc/<service>/<service>.conf.d
	// all other files get placed into /etc/<service> to allow overwrite of e.g. logging.conf or policy.json
	// TODO: make sure custom.conf can not be overwritten
	customData := map[string]string{
		common.CustomServiceConfigFileName: instance.Spec.CustomServiceConfig,
		"my.cnf":                           octaviaDb.GetDatabaseClientConfig(tlsCfg), //(mschuppert) for now just get the default my.cnf
	}
	for key, data := range instance.Spec.DefaultConfigOverwrite {
		customData[key] = data
	}

	databaseAccount := octaviaDb.GetAccount()
	dbSecret := octaviaDb.GetSecret()
	persistenceDatabaseAccount := persistenceDb.GetAccount()
	persistenceDbSecret := persistenceDb.GetSecret()

	// We only need a minimal 00-config.conf that is only used by db-sync job,
	// hence only passing the database related parameters
	templateParameters := map[string]interface{}{
		"MinimalConfig": true, // This tells the template to generate a minimal config
		"DatabaseConnection": fmt.Sprintf("mysql+pymysql://%s:%s@%s/%s?read_default_file=/etc/my.cnf",
			databaseAccount.Spec.UserName,
			string(dbSecret.Data[mariadbv1.DatabasePasswordSelector]),
			instance.Status.DatabaseHostname,
			octavia.DatabaseName,
		),
		"PersistenceDatabaseConnection": fmt.Sprintf("mysql+pymysql://%s:%s@%s/%s?read_default_file=/etc/my.cnf",
			persistenceDatabaseAccount.Spec.UserName,
			string(persistenceDbSecret.Data[mariadbv1.DatabasePasswordSelector]),
			instance.Status.DatabaseHostname,
			octavia.PersistenceDatabaseName,
		),
	}
	templateParameters["ServiceUser"] = instance.Spec.ServiceUser

	cms := []util.Template{
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
	err := oko_secret.EnsureSecrets(ctx, h, instance, cms, envVars)
	if err != nil {
		return err
	}

	return nil
}

// createHashOfInputHashes - creates a hash of hashes which gets added to the resources which requires a restart
// if any of the input resources change, like configs, passwords, ...
//
// returns the hash, whether the hash changed (as a bool) and any error
func (r *OctaviaReconciler) createHashOfInputHashes(
	ctx context.Context,
	instance *octaviav1.Octavia,
	envVars map[string]env.Setter,
) (string, bool, error) {
	Log := r.GetLogger(ctx)
	var hashMap map[string]string
	changed := false
	mergedMapVars := env.MergeEnvs([]corev1.EnvVar{}, envVars)
	hash, err := util.ObjectHash(mergedMapVars)
	if err != nil {
		return hash, changed, err
	}
	if hashMap, changed = util.SetHash(instance.Status.Hash, common.InputHashName, hash); changed {
		instance.Status.Hash = hashMap
		Log.Info(fmt.Sprintf("Input maps hash %s - %s", common.InputHashName, hash))
	}
	return hash, changed, nil
}

func (r *OctaviaReconciler) apiDeploymentCreateOrUpdate(instance *octaviav1.Octavia) (*octaviav1.OctaviaAPI, controllerutil.OperationResult, error) {
	deployment := &octaviav1.OctaviaAPI{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-api", instance.Name),
			Namespace: instance.Namespace,
		},
	}

	op, err := controllerutil.CreateOrUpdate(context.TODO(), r.Client, deployment, func() error {
		deployment.Spec = instance.Spec.OctaviaAPI
		deployment.Spec.DatabaseInstance = instance.Spec.DatabaseInstance
		deployment.Spec.DatabaseHostname = instance.Status.DatabaseHostname
		deployment.Spec.DatabaseAccount = instance.Spec.DatabaseAccount
		deployment.Spec.PersistenceDatabaseAccount = instance.Spec.PersistenceDatabaseAccount
		deployment.Spec.ServiceUser = instance.Spec.ServiceUser
		deployment.Spec.TransportURLSecret = instance.Status.TransportURLSecret
		deployment.Spec.Secret = instance.Spec.Secret
		deployment.Spec.ServiceAccount = instance.RbacResourceName()
		deployment.Spec.TLS = instance.Spec.OctaviaAPI.TLS
		deployment.Spec.APITimeout = instance.Spec.APITimeout

		if len(deployment.Spec.NodeSelector) == 0 {
			deployment.Spec.NodeSelector = instance.Spec.NodeSelector
		}
		err := controllerutil.SetControllerReference(instance, deployment, r.Scheme)
		if err != nil {
			return err
		}
		return nil
	})

	return deployment, op, err
}

func (r *OctaviaReconciler) transportURLCreateOrUpdate(
	instance *octaviav1.Octavia,
) (*rabbitmqv1.TransportURL,
	controllerutil.OperationResult, error) {
	transportURL := &rabbitmqv1.TransportURL{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-octavia-transport", instance.Name),
			Namespace: instance.Namespace,
		},
	}

	op, err := controllerutil.CreateOrUpdate(context.TODO(), r.Client, transportURL, func() error {
		transportURL.Spec.RabbitmqClusterName = instance.Spec.RabbitMqClusterName
		err := controllerutil.SetControllerReference(instance, transportURL, r.Scheme)
		return err
	})
	return transportURL, op, err
}

func (r *OctaviaReconciler) amphoraControllerDaemonSetCreateOrUpdate(
	instance *octaviav1.Octavia,
	networkInfo octavia.NetworkProvisioningSummary,
	ampImageOwnerID string,
	controllerSpec octaviav1.OctaviaAmphoraControllerSpec,
	role string,
) (*octaviav1.OctaviaAmphoraController,
	controllerutil.OperationResult, error) {

	daemonset := &octaviav1.OctaviaAmphoraController{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", instance.Name, role),
			Namespace: instance.Namespace,
		},
	}

	op, err := controllerutil.CreateOrUpdate(context.TODO(), r.Client, daemonset, func() error {
		daemonset.Spec = controllerSpec
		daemonset.Spec.Role = role
		daemonset.Spec.DatabaseInstance = instance.Spec.DatabaseInstance
		daemonset.Spec.DatabaseHostname = instance.Status.DatabaseHostname
		daemonset.Spec.DatabaseAccount = instance.Spec.DatabaseAccount
		daemonset.Spec.PersistenceDatabaseAccount = instance.Spec.PersistenceDatabaseAccount
		daemonset.Spec.ServiceUser = instance.Spec.ServiceUser
		daemonset.Spec.Secret = instance.Spec.Secret
		daemonset.Spec.TransportURLSecret = instance.Status.TransportURLSecret
		daemonset.Spec.ServiceAccount = instance.RbacResourceName()
		daemonset.Spec.LbMgmtNetworkID = networkInfo.TenantNetworkID
		daemonset.Spec.LbSecurityGroupID = networkInfo.SecurityGroupID
		daemonset.Spec.AmphoraCustomFlavors = instance.Spec.AmphoraCustomFlavors
		daemonset.Spec.TLS = instance.Spec.OctaviaAPI.TLS.Ca
		daemonset.Spec.AmphoraImageOwnerID = ampImageOwnerID
		daemonset.Spec.OctaviaProviderSubnetGateway = networkInfo.ManagementSubnetGateway
		daemonset.Spec.OctaviaProviderSubnetCIDR = networkInfo.ManagementSubnetCIDR
		daemonset.Spec.OctaviaProviderSubnetExtraCIDRs = networkInfo.ManagementSubnetExtraCIDRs
		if len(daemonset.Spec.NodeSelector) == 0 {
			daemonset.Spec.NodeSelector = instance.Spec.NodeSelector
		}
		err := controllerutil.SetControllerReference(instance, daemonset, r.Scheme)
		if err != nil {
			return err
		}
		return nil
	})

	return daemonset, op, err
}

func amphoraControllerReadyCondition(role string) condition.Type {
	condMap := map[string]condition.Type{
		octaviav1.HealthManager: octaviav1.OctaviaHealthManagerReadyCondition,
		octaviav1.Housekeeping:  octaviav1.OctaviaHousekeepingReadyCondition,
		octaviav1.Worker:        octaviav1.OctaviaWorkerReadyCondition,
	}
	return condMap[role]
}

func amphoraControllerInitCondition(role string) *condition.Condition {
	condMap := map[string]*condition.Condition{
		octaviav1.HealthManager: condition.UnknownCondition(
			amphoraControllerReadyCondition(role),
			condition.InitReason,
			octaviav1.OctaviaHealthManagerReadyInitMessage),
		octaviav1.Housekeeping: condition.UnknownCondition(
			amphoraControllerReadyCondition(role),
			condition.InitReason,
			octaviav1.OctaviaHousekeepingReadyInitMessage),
		octaviav1.Worker: condition.UnknownCondition(
			amphoraControllerReadyCondition(role),
			condition.InitReason,
			octaviav1.OctaviaWorkerReadyInitMessage),
	}
	return condMap[role]
}

func amphoraControllerErrorMessage(role string) string {
	condMap := map[string]string{
		octaviav1.HealthManager: octaviav1.OctaviaHealthManagerReadyErrorMessage,
		octaviav1.Housekeeping:  octaviav1.OctaviaHousekeepingReadyErrorMessage,
		octaviav1.Worker:        octaviav1.OctaviaWorkerReadyErrorMessage,
	}
	return condMap[role]
}

func (r *OctaviaReconciler) octaviaRsyslogDaemonSetCreateOrUpdate(
	instance *octaviav1.Octavia,
	controllerSpec octaviav1.OctaviaRsyslogSpec,
) (*octaviav1.OctaviaRsyslog,
	controllerutil.OperationResult, error) {

	daemonset := &octaviav1.OctaviaRsyslog{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-rsyslog", instance.Name),
			Namespace: instance.Namespace,
		},
	}

	op, err := controllerutil.CreateOrUpdate(context.TODO(), r.Client, daemonset, func() error {
		daemonset.Spec = controllerSpec
		daemonset.Spec.ServiceUser = instance.Spec.ServiceUser
		daemonset.Spec.ServiceAccount = instance.RbacResourceName()
		if len(daemonset.Spec.NodeSelector) == 0 {
			daemonset.Spec.NodeSelector = instance.Spec.NodeSelector
		}
		err := controllerutil.SetControllerReference(instance, daemonset, r.Scheme)
		if err != nil {
			return err
		}
		return nil
	})

	return daemonset, op, err
}

// checkOctaviaAPIGeneration -
func (r *OctaviaReconciler) checkOctaviaAPIGeneration(
	instance *octaviav1.Octavia,
) (bool, error) {
	api := &octaviav1.OctaviaAPIList{}
	listOpts := []client.ListOption{
		client.InNamespace(instance.Namespace),
	}
	if err := r.Client.List(context.Background(), api, listOpts...); err != nil {
		r.Log.Error(err, "Unable to retrieve OctaviaAPI %w")
		return false, err
	}
	for _, item := range api.Items {
		if item.Generation != item.Status.ObservedGeneration {
			return false, nil
		}
	}
	return true, nil
}

// checkAmphoraGeneration -
func (r *OctaviaReconciler) checkAmphoraGeneration(
	instance *octaviav1.Octavia,
) (bool, error) {
	amph := &octaviav1.OctaviaAmphoraControllerList{}
	listOpts := []client.ListOption{
		client.InNamespace(instance.Namespace),
	}
	if err := r.Client.List(context.Background(), amph, listOpts...); err != nil {
		r.Log.Error(err, "Unable to retrieve OctaviaAPI %w")
		return false, err
	}
	for _, item := range amph.Items {
		if item.Generation != item.Status.ObservedGeneration {
			return false, nil
		}
	}
	return true, nil
}
