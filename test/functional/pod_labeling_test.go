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

package functional_test

import (
	"fmt"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2" //revive:disable:dot-imports
	. "github.com/onsi/gomega"    //revive:disable:dot-imports

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/openstack-k8s-operators/lib-common/modules/common"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/octavia-operator/internal/controller"
	"github.com/openstack-k8s-operators/octavia-operator/internal/octavia"
)

var _ = Describe("Pod Labeling", func() {
	var (
		configMapName      types.NamespacedName
		healthManagerPod   *corev1.Pod
		rsyslogPod         *corev1.Pod
		existingLabeledPod *corev1.Pod
	)

	BeforeEach(func() {
		configMapName = types.NamespacedName{
			Name:      "octavia-hmport-map",
			Namespace: namespace,
		}

		// Create configmap with test data
		configMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      configMapName.Name,
				Namespace: configMapName.Namespace,
			},
			Data: map[string]string{
				"hm_worker-1":      "172.23.0.100",
				"hm_worker-2":      "172.23.0.101",
				"rsyslog_worker-1": "172.23.0.200",
				"rsyslog_worker-2": "172.23.0.201",
			},
		}
		Expect(k8sClient.Create(ctx, configMap)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ctx, configMap)

		// Create test pods
		healthManagerPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("healthmanager-pod-%s", uuid.New().String()[:8]),
				Namespace: namespace,
				Labels: map[string]string{
					common.AppSelector: "octavia-healthmanager",
				},
			},
			Spec: corev1.PodSpec{
				NodeName: "worker-1",
				Containers: []corev1.Container{{
					Name:  "test-container",
					Image: "test-image",
				}},
			},
		}
		Expect(k8sClient.Create(ctx, healthManagerPod)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ctx, healthManagerPod)

		rsyslogPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("rsyslog-pod-%s", uuid.New().String()[:8]),
				Namespace: namespace,
				Labels: map[string]string{
					common.AppSelector: "octavia-rsyslog",
				},
			},
			Spec: corev1.PodSpec{
				NodeName: "worker-2",
				Containers: []corev1.Container{{
					Name:  "test-container",
					Image: "test-image",
				}},
			},
		}
		Expect(k8sClient.Create(ctx, rsyslogPod)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ctx, rsyslogPod)

		// Create pod with existing predictableip label
		existingLabeledPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("existing-labeled-pod-%s", uuid.New().String()[:8]),
				Namespace: namespace,
				Labels: map[string]string{
					common.AppSelector: "octavia-rsyslog",
					"predictableip":    "existing-ip",
				},
			},
			Spec: corev1.PodSpec{
				NodeName: "worker-1",
				Containers: []corev1.Container{{
					Name:  "test-container",
					Image: "test-image",
				}},
			},
		}
		Expect(k8sClient.Create(ctx, existingLabeledPod)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ctx, existingLabeledPod)
	})

	Context("HandlePodLabeling function", func() {
		It("should label healthmanager pods with hm_ IP addresses", func() {
			// Create helper
			dummyInstance := &octaviav1.OctaviaAmphoraController{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-healthmanager",
					Namespace: namespace,
				},
			}
			h, err := helper.NewHelper(
				dummyInstance,
				k8sClient,
				nil, // No kclient needed for this test
				k8sClient.Scheme(),
				zap.New(zap.UseDevMode(true)), // Test logger
			)
			Expect(err).NotTo(HaveOccurred())

			config := controller.PodLabelingConfig{
				ConfigMapName: octavia.HmConfigMap,
				IPKeyPrefix:   "hm_",
				ServiceName:   "octavia-healthmanager",
			}

			err = controller.HandlePodLabeling(ctx, h, "octavia-healthmanager", namespace, config)
			Expect(err).NotTo(HaveOccurred())

			// Verify the pod got labeled correctly
			Eventually(func(g Gomega) {
				pod := &corev1.Pod{}
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      healthManagerPod.Name,
					Namespace: namespace,
				}, pod)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(pod.Labels).To(HaveKeyWithValue("predictableip", "172.23.0.100"))
			}, timeout, interval).Should(Succeed())
		})

		It("should label rsyslog pods with rsyslog_ IP addresses", func() {
			// Create helper
			dummyInstance := &octaviav1.OctaviaAmphoraController{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-rsyslog",
					Namespace: namespace,
				},
			}
			h, err := helper.NewHelper(
				dummyInstance,
				k8sClient,
				nil, // No kclient needed for this test
				k8sClient.Scheme(),
				zap.New(zap.UseDevMode(true)), // Test logger
			)
			Expect(err).NotTo(HaveOccurred())

			config := controller.PodLabelingConfig{
				ConfigMapName: octavia.HmConfigMap,
				IPKeyPrefix:   "rsyslog_",
				ServiceName:   "octavia-rsyslog",
			}

			err = controller.HandlePodLabeling(ctx, h, "octavia-rsyslog", namespace, config)
			Expect(err).NotTo(HaveOccurred())

			// Verify the pod got labeled correctly
			Eventually(func(g Gomega) {
				pod := &corev1.Pod{}
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      rsyslogPod.Name,
					Namespace: namespace,
				}, pod)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(pod.Labels).To(HaveKeyWithValue("predictableip", "172.23.0.201"))
			}, timeout, interval).Should(Succeed())
		})

		It("should skip pods that already have correct predictableip labels", func() {
			// Create helper
			dummyInstance := &octaviav1.OctaviaAmphoraController{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-existing",
					Namespace: namespace,
				},
			}
			h, err := helper.NewHelper(
				dummyInstance,
				k8sClient,
				nil, // No kclient needed for this test
				k8sClient.Scheme(),
				zap.New(zap.UseDevMode(true)), // Test logger
			)
			Expect(err).NotTo(HaveOccurred())

			config := controller.PodLabelingConfig{
				ConfigMapName: octavia.HmConfigMap,
				IPKeyPrefix:   "rsyslog_",
				ServiceName:   "octavia-rsyslog",
			}

			err = controller.HandlePodLabeling(ctx, h, "octavia-rsyslog", namespace, config)
			Expect(err).NotTo(HaveOccurred())

			// Verify the label was updated to match configmap
			Eventually(func(g Gomega) {
				pod := &corev1.Pod{}
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      existingLabeledPod.Name,
					Namespace: namespace,
				}, pod)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(pod.Labels).To(HaveKeyWithValue("predictableip", "172.23.0.200"))
			}, timeout, interval).Should(Succeed())
		})

		It("should update IP label when pod has stale IP from different node", func() {
			// Create a pod on worker-2 but with stale label from worker-1
			// This simulates a defensive scenario where label somehow got out of sync
			stalePod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("stale-pod-%s", uuid.New().String()[:8]),
					Namespace: namespace,
					Labels: map[string]string{
						common.AppSelector: "octavia-rsyslog",
						"predictableip":    "172.23.0.200", // Stale IP for worker-1
					},
				},
				Spec: corev1.PodSpec{
					NodeName: "worker-2", // Actually on worker-2
					Containers: []corev1.Container{{
						Name:  "test-container",
						Image: "test-image",
					}},
				},
			}
			Expect(k8sClient.Create(ctx, stalePod)).To(Succeed())
			DeferCleanup(k8sClient.Delete, ctx, stalePod)

			// Create helper and run labeling
			dummyInstance := &octaviav1.OctaviaAmphoraController{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-stale",
					Namespace: namespace,
				},
			}
			h, err := helper.NewHelper(
				dummyInstance,
				k8sClient,
				nil,
				k8sClient.Scheme(),
				zap.New(zap.UseDevMode(true)),
			)
			Expect(err).NotTo(HaveOccurred())

			config := controller.PodLabelingConfig{
				ConfigMapName: octavia.HmConfigMap,
				IPKeyPrefix:   "rsyslog_",
				ServiceName:   "octavia-rsyslog",
			}

			err = controller.HandlePodLabeling(ctx, h, "octavia-rsyslog", namespace, config)
			Expect(err).NotTo(HaveOccurred())

			// Verify the label was corrected to match the current node's IP
			Eventually(func(g Gomega) {
				pod := &corev1.Pod{}
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      stalePod.Name,
					Namespace: namespace,
				}, pod)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(pod.Labels).To(HaveKeyWithValue("predictableip", "172.23.0.201"))
			}, timeout, interval).Should(Succeed())
		})
	})
})
