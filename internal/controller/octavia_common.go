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

package controller

import (
	"context"
	"fmt"

	networkv1 "github.com/openstack-k8s-operators/infra-operator/apis/network/v1beta1"
	topologyv1 "github.com/openstack-k8s-operators/infra-operator/apis/topology/v1beta1"
	"github.com/openstack-k8s-operators/lib-common/modules/common"
	"github.com/openstack-k8s-operators/lib-common/modules/common/condition"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type conditionUpdater interface {
	Set(c *condition.Condition)
	MarkTrue(t condition.Type, messageFormat string, messageArgs ...any)
}

type topologyHandler interface {
	GetSpecTopologyRef() *topologyv1.TopoRef
	GetLastAppliedTopology() *topologyv1.TopoRef
	SetLastAppliedTopology(t *topologyv1.TopoRef)
}

func ensureTopology(
	ctx context.Context,
	helper *helper.Helper,
	instance topologyHandler,
	finalizer string,
	conditionUpdater conditionUpdater,
	defaultLabelSelector metav1.LabelSelector,
) (*topologyv1.Topology, error) {

	topology, err := topologyv1.EnsureServiceTopology(
		ctx,
		helper,
		instance.GetSpecTopologyRef(),
		instance.GetLastAppliedTopology(),
		finalizer,
		defaultLabelSelector,
	)
	if err != nil {
		conditionUpdater.Set(condition.FalseCondition(
			condition.TopologyReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			condition.TopologyReadyErrorMessage,
			err.Error()))
		return nil, fmt.Errorf("waiting for Topology requirements: %w", err)
	}
	// update the Status with the last retrieved Topology (or set it to nil)
	instance.SetLastAppliedTopology(instance.GetSpecTopologyRef())
	// update the Topology condition only when a Topology is referenced and has
	// been retrieved (err == nil)
	if tr := instance.GetSpecTopologyRef(); tr != nil {
		// update the TopologyRef associated condition
		conditionUpdater.MarkTrue(
			condition.TopologyReadyCondition,
			condition.TopologyReadyMessage,
		)
	}
	return topology, nil
}

// PodLabelingConfig contains configuration for pod labeling
type PodLabelingConfig struct {
	ConfigMapName string
	IPKeyPrefix   string
	ServiceName   string
}

// HandlePodLabeling adds predictableip labels to all pods owned by the specified instance
func HandlePodLabeling(ctx context.Context, helper *helper.Helper, instanceName, namespace string, config PodLabelingConfig) error {
	// Get the ConfigMap once
	configMap := &corev1.ConfigMap{}
	if err := helper.GetClient().Get(ctx, types.NamespacedName{Name: config.ConfigMapName, Namespace: namespace}, configMap); err != nil {
		return fmt.Errorf("failed to get configmap %s: %w", config.ConfigMapName, err)
	}

	// List all pods owned by this instance
	podList := &corev1.PodList{}
	listOpts := []client.ListOption{
		client.InNamespace(namespace),
		client.MatchingLabels(map[string]string{
			common.AppSelector: instanceName,
		}),
	}

	if err := helper.GetClient().List(ctx, podList, listOpts...); err != nil {
		return fmt.Errorf("failed to list pods: %w", err)
	}

	// Process each pod
	for i := range podList.Items {
		pod := &podList.Items[i]

		// Skip if no node assigned
		if pod.Spec.NodeName == "" {
			continue
		}

		// Get predictable IP from configmap
		ipKey := fmt.Sprintf("%s%s", config.IPKeyPrefix, pod.Spec.NodeName)
		predictableIP, exists := configMap.Data[ipKey]
		if !exists {
			continue // Skip pods without predictable IPs
		}

		// Skip if label already matches
		if pod.Labels != nil && pod.Labels[networkv1.PredictableIPLabel] == predictableIP {
			continue
		}

		// Add or update the label
		if pod.Labels == nil {
			pod.Labels = make(map[string]string)
		}
		pod.Labels[networkv1.PredictableIPLabel] = predictableIP

		if err := helper.GetClient().Update(ctx, pod); err != nil {
			log.FromContext(ctx).Error(err, "Failed to update pod", "pod", pod.Name, "predictableIP", predictableIP)
		}
	}

	return nil
}
