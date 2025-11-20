/*
Copyright 2024.

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
	"encoding/json"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2" //revive:disable:dot-imports
	. "github.com/onsi/gomega"    //revive:disable:dot-imports

	networkv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	rabbitmqv1 "github.com/openstack-k8s-operators/infra-operator/apis/rabbitmq/v1beta1"
	condition "github.com/openstack-k8s-operators/lib-common/modules/common/condition"
	"github.com/openstack-k8s-operators/lib-common/modules/common/endpoint"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/octavia-operator/internal/octavia"
)

const (
	SecretName         = "test-secret"
	KeystoneSecretName = "%s-keystone-secret" // #nosec G101 -- Test constant, not a credential
	RabbitmqSecretName = "rabbitmq-secret"

	PublicCertSecretName   = "public-tls-certs"   // #nosec G101 -- Test constant, not a credential
	InternalCertSecretName = "internal-tls-certs" // #nosec G101 -- Test constant, not a credential
	CABundleSecretName     = "combined-ca-bundle" // #nosec G101 -- Test constant, not a credential

	OVNNBDBEndpoint = "ovnnbdbendpoint:1234"
	OVNSBDBEndpoint = "ovnsbdbendpoint:1234"

	timeout  = time.Second * 25
	interval = timeout / 100
)

func CreateTransportURL(name types.NamespacedName) *rabbitmqv1.TransportURL {
	transportURL := &rabbitmqv1.TransportURL{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name.Name,
			Namespace: name.Namespace,
		},
		Spec: rabbitmqv1.TransportURLSpec{
			RabbitmqClusterName: "rabbitmq",
		},
	}
	Expect(k8sClient.Create(ctx, transportURL)).Should(Succeed())
	return infra.GetTransportURL(name)
}

func CreateTransportURLSecret(name types.NamespacedName) *corev1.Secret {
	secret := th.CreateSecret(
		name,
		map[string][]byte{
			"transport_url": fmt.Appendf(nil, "rabbit://%s/", name),
		},
	)
	logger.Info("Created TransportURLSecret", "secret", secret)
	return secret
}

func SimulateKeystoneReady(
	name types.NamespacedName,
	publicEndpointURL string,
	internalEndpointURL string,
) {
	secretName := fmt.Sprintf(KeystoneSecretName, name.Name)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"admin-password": []byte("12345678"),
		},
	}
	Expect(k8sClient.Create(ctx, secret)).Should(Succeed())
	DeferCleanup(k8sClient.Delete, ctx, secret)
	Eventually(func(g Gomega) {
		ks := keystone.GetKeystoneAPI(name)
		ks.Spec.Secret = secretName
		ks.Spec.Region = "RegionOne"
		ks.Spec.AdminProject = "admin"
		g.Expect(k8sClient.Update(ctx, ks)).To(Succeed())
		ks.Status.APIEndpoints[string(endpoint.EndpointInternal)] = internalEndpointURL
		ks.Status.APIEndpoints[string(endpoint.EndpointPublic)] = publicEndpointURL
		g.Expect(k8sClient.Status().Update(ctx, ks)).To(Succeed())
	}, timeout, interval).Should(Succeed())
}

func GetDefaultOctaviaSpec() map[string]any {
	return map[string]any{
		"databaseInstance":           "test-octavia-db-instance",
		"secret":                     SecretName,
		"octaviaNetworkAttachment":   "octavia-attachement",
		"databaseAccount":            "octavia-db-account",
		"persistenceDatabaseAccount": "octavia-persistence-db-account",
		"lbMgmtNetwork": map[string]any{
			"availabilityZones": []string{"az0"},
			// It seems that the functional tests don't use the correct default
			// values for nested structures, when the default is defined in the
			// parent struct
			"manageLbMgmtNetworks":       true,
			"createDefaultLbMgmtNetwork": true,
		},
	}
}

func CreateOctavia(name types.NamespacedName, spec map[string]any) client.Object {

	raw := map[string]any{
		"apiVersion": "octavia.openstack.org/v1beta1",
		"kind":       "Octavia",
		"metadata": map[string]any{
			"name":      name.Name,
			"namespace": name.Namespace,
		},
		"spec": spec,
	}
	return th.CreateUnstructured(raw)
}

func GetOctavia(name types.NamespacedName) *octaviav1.Octavia {
	instance := &octaviav1.Octavia{}
	Eventually(func(g Gomega) {
		g.Expect(k8sClient.Get(ctx, name, instance)).Should(Succeed())
	}, timeout, interval).Should(Succeed())
	return instance
}

func OctaviaConditionGetter(name types.NamespacedName) condition.Conditions {
	instance := GetOctavia(name)
	return instance.Status.Conditions
}

func CreateOctaviaSecret(namespace string) *corev1.Secret {
	secret := th.CreateSecret(
		types.NamespacedName{Namespace: namespace, Name: SecretName},
		map[string][]byte{
			"OctaviaPassword": []byte("OctaviaPassword12345678"),
		},
	)
	logger.Info("Secret created", "name", SecretName, "namespace", namespace)
	return secret
}

func CreateOctaviaCaPassphraseSecretCustom(namespace string, name string, passphrase string) *corev1.Secret {
	return th.CreateSecret(
		types.NamespacedName{
			Namespace: namespace,
			Name:      fmt.Sprintf("%s-ca-passphrase", name),
		},
		map[string][]byte{
			"server-ca-passphrase": []byte(passphrase),
		},
	)
}

func CreateOctaviaCaPassphraseSecret(namespace string, name string) *corev1.Secret {
	return CreateOctaviaCaPassphraseSecretCustom(namespace, name, "12345678")
}

func SimulateOctaviaCertsSecret(namespace string, name string) *corev1.Secret {
	secretName := fmt.Sprintf("%s-certs-secret", name)
	secret := th.CreateSecret(
		types.NamespacedName{
			Name:      secretName,
			Namespace: namespace,
		},
		map[string][]byte{
			"server_ca.key.pem":       []byte("secret ca key data"),
			"server_ca.cert.pem":      []byte("secret ca cert data"),
			"client_ca.cert.pem":      []byte("client ca cert data"),
			"client.cert-and-key.pem": []byte("client cert and key data"),
		},
	)
	logger.Info("Created Octavia Certs Secret", "secret", secret)
	return secret
}

// OctaviaAPI
func GetDefaultOctaviaAPISpec() map[string]any {
	return map[string]any{
		"databaseHostname": "hostname-for-octavia-api",
		"databaseInstance": "test-octavia-db-instance",
		"secret":           SecretName,
		"containerImage":   "repo/octavia-api-image",
		"serviceAccount":   "octavia",
	}
}

func CreateOctaviaAPI(name types.NamespacedName, spec map[string]any) client.Object {
	raw := map[string]any{
		"apiVersion": "octavia.openstack.org/v1beta1",
		"kind":       "OctaviaAPI",
		"metadata": map[string]any{
			"name":      name.Name,
			"namespace": name.Namespace,
		},
		"spec": spec,
	}
	return th.CreateUnstructured(raw)
}

func GetOctaviaAPI(name types.NamespacedName) *octaviav1.OctaviaAPI {
	instance := &octaviav1.OctaviaAPI{}
	Eventually(func(g Gomega) {
		g.Expect(k8sClient.Get(ctx, name, instance)).Should(Succeed())
	}, timeout, interval).Should(Succeed())
	return instance
}

func OctaviaAPIConditionGetter(name types.NamespacedName) condition.Conditions {
	instance := GetOctaviaAPI(name)
	return instance.Status.Conditions
}

func SimulateOctaviaAPIReady(name types.NamespacedName) {
	Eventually(func(g Gomega) {
		octaviaAPI := GetOctaviaAPI(name)
		octaviaAPI.Status.ObservedGeneration = octaviaAPI.Generation
		octaviaAPI.Status.ReadyCount = 1
		g.Expect(k8sClient.Status().Update(ctx, octaviaAPI)).To(Succeed())
	}, timeout, interval).Should(Succeed())
}

func CreateNAD(name types.NamespacedName) client.Object {
	raw := map[string]any{
		"apiVersion": "k8s.cni.cncf.io/v1",
		"kind":       "NetworkAttachmentDefinition",
		"metadata": map[string]any{
			"name":      name.Name,
			"namespace": name.Namespace,
		},
		"spec": map[string]any{
			"config": `{
				"cniVersion": "0.3.1",
				"name": "octavia",
				"type": "bridge",
				"bridge": "octbr",
				"ipam": {
				    "type": "whereabouts",
				    "range": "172.23.0.0/24",
				    "range_start": "172.23.0.30",
				    "range_end": "172.23.0.70",
				    "routes": [{
				        "dst": "172.24.0.0/16",
				        "gw" : "172.23.0.150"
		            }]
		        }
			}`,
		},
	}
	return th.CreateUnstructured(raw)
}

func GetNADConfig(name types.NamespacedName) *octavia.NADConfig {
	nad := &networkv1.NetworkAttachmentDefinition{}
	Eventually(func(g Gomega) {
		g.Expect(k8sClient.Get(ctx, name, nad)).Should(Succeed())
	}, timeout, interval).Should(Succeed())

	nadConfig := &octavia.NADConfig{}
	jsonDoc := []byte(nad.Spec.Config)
	err := json.Unmarshal(jsonDoc, nadConfig)
	if err != nil {
		return nil
	}

	return nadConfig
}

func CreateNode(name types.NamespacedName) client.Object {
	raw := map[string]any{
		"apiVersion": "v1",
		"kind":       "Node",
		"metadata": map[string]any{
			"name":      name.Name,
			"namespace": name.Namespace,
		},
		"spec": map[string]any{},
	}
	return th.CreateUnstructured(raw)

}

func CreateSSHPubKey() client.Object {
	return th.CreateConfigMap(types.NamespacedName{
		Name:      "octavia-ssh-pubkey",
		Namespace: namespace,
	}, map[string]any{
		"key": "public key",
	})
}
