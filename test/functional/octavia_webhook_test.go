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

package functional_test

import (
	"errors"

	. "github.com/onsi/ginkgo/v2" //revive:disable:dot-imports
	. "github.com/onsi/gomega"    //revive:disable:dot-imports

	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

var _ = Describe("Octavia webhook", func() {
	It("rejects update to deprecated rabbitMqClusterName field", func() {
		spec := GetDefaultOctaviaSpec()
		spec["rabbitMqClusterName"] = "rabbitmq"

		octaviaName := types.NamespacedName{
			Namespace: namespace,
			Name:      "octavia-webhook-test",
		}

		raw := map[string]any{
			"apiVersion": "octavia.openstack.org/v1beta1",
			"kind":       "Octavia",
			"metadata": map[string]any{
				"name":      octaviaName.Name,
				"namespace": octaviaName.Namespace,
			},
			"spec": spec,
		}

		// Create the Octavia instance
		unstructuredObj := &unstructured.Unstructured{Object: raw}
		_, err := controllerutil.CreateOrPatch(
			ctx, k8sClient, unstructuredObj, func() error { return nil })
		Expect(err).ShouldNot(HaveOccurred())

		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, unstructuredObj)
		})

		// Try to update rabbitMqClusterName
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, octaviaName, unstructuredObj)).Should(Succeed())
			specMap := unstructuredObj.Object["spec"].(map[string]any)
			specMap["rabbitMqClusterName"] = "rabbitmq2"
			err := k8sClient.Update(ctx, unstructuredObj)
			g.Expect(err).Should(HaveOccurred())

			var statusError *k8s_errors.StatusError
			g.Expect(errors.As(err, &statusError)).To(BeTrue())
			g.Expect(statusError.ErrStatus.Details.Kind).To(Equal("Octavia"))
			g.Expect(statusError.ErrStatus.Message).To(
				ContainSubstring("field \"spec.rabbitMqClusterName\" is deprecated"))
			g.Expect(statusError.ErrStatus.Message).To(
				ContainSubstring("use \"spec.messagingBus.cluster\" instead"))
		}, timeout, interval).Should(Succeed())
	})

	DescribeTable("validates octaviaAPI service override",
		func(endpoint string, override map[string]any, errSubstr string) {
			spec := GetDefaultOctaviaSpec()
			spec["octaviaAPI"] = map[string]any{
				"override": map[string]any{
					"service": map[string]any{endpoint: override},
				},
			}
			raw := map[string]any{
				"apiVersion": "octavia.openstack.org/v1beta1",
				"kind":       "Octavia",
				"metadata": map[string]any{
					"name":      "octavia-override-webhook-test",
					"namespace": namespace,
				},
				"spec": spec,
			}
			obj := &unstructured.Unstructured{Object: raw}
			_, err := controllerutil.CreateOrPatch(
				ctx, k8sClient, obj, func() error { return nil })
			if errSubstr == "" {
				Expect(err).ShouldNot(HaveOccurred())
				DeferCleanup(func() { _ = k8sClient.Delete(ctx, obj) })
				return
			}
			Expect(err).Should(HaveOccurred())
			var statusError *k8s_errors.StatusError
			Expect(errors.As(err, &statusError)).To(BeTrue())
			Expect(statusError.ErrStatus.Message).To(ContainSubstring(errSubstr))
		},
		Entry("public bare port name accepted", "public", portOverride("public", 443), ""),
		Entry("internal bare port name accepted", "internal", portOverride("internal", 443), ""),
		Entry("public wrong port name rejected", "public", portOverride("octavia-public", 443), `must be "public"`),
		Entry("internal wrong port name rejected", "internal", portOverride("octavia-internal", 443), `must be "internal"`),
		Entry("public FQDN endpointURL accepted", "public",
			map[string]any{"endpointURL": "https://octavia.example.com:9876"}, ""),
		Entry("internal FQDN endpointURL accepted", "internal",
			map[string]any{"endpointURL": "https://octavia-int.example.com:9876"}, ""),
		Entry("public short name endpointURL rejected", "public",
			map[string]any{"endpointURL": "https://octavia:9876"}, "endpointURL"),
		Entry("internal short name endpointURL rejected", "internal",
			map[string]any{"endpointURL": "https://octavia:9876"}, "endpointURL"),
		Entry("public missing scheme rejected", "public",
			map[string]any{"endpointURL": "octavia.example.com:9876"}, "endpointURL"),
		Entry("public IP literal rejected", "public",
			map[string]any{"endpointURL": "https://192.168.1.1:9876"}, "endpointURL"),
		Entry("internal IP literal rejected", "internal",
			map[string]any{"endpointURL": "https://192.168.1.1:9876"}, "endpointURL"),
		Entry("public port differing from endpointURL port rejected", "public",
			map[string]any{
				"endpointURL": "https://octavia.example.com:9876",
				"spec":        map[string]any{"ports": []any{map[string]any{"name": "public", "port": 443}}},
			}, "endpointURL"),
		Entry("internal port matching endpointURL port accepted", "internal",
			map[string]any{
				"endpointURL": "https://octavia-int.example.com:8443",
				"spec":        map[string]any{"ports": []any{map[string]any{"name": "internal", "port": 8443}}},
			}, ""),
	)
})

func portOverride(name string, port int) map[string]any {
	return map[string]any{
		"spec": map[string]any{"ports": []any{map[string]any{"name": name, "port": port}}},
	}
}
