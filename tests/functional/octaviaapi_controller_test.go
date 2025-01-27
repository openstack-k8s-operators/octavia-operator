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
	"fmt"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2" //revive:disable:dot-imports
	. "github.com/onsi/gomega"    //revive:disable:dot-imports
	"k8s.io/apimachinery/pkg/types"

	corev1 "k8s.io/api/core/v1"

	"github.com/openstack-k8s-operators/lib-common/modules/common"
	"github.com/openstack-k8s-operators/lib-common/modules/common/condition"

	//revive:disable-next-line:dot-imports
	. "github.com/openstack-k8s-operators/lib-common/modules/common/test/helpers"
	"github.com/openstack-k8s-operators/octavia-operator/pkg/octavia"

	mariadbv1 "github.com/openstack-k8s-operators/mariadb-operator/api/v1beta1"
	ovnv1 "github.com/openstack-k8s-operators/ovn-operator/api/v1beta1"
)

var _ = Describe("OctaviaAPI controller", func() {
	var name string
	var spec map[string]interface{}
	var octaviaAPIName types.NamespacedName
	var transportURLSecretName types.NamespacedName

	BeforeEach(func() {
		name = fmt.Sprintf("octavia-api-%s", uuid.New().String())
		spec = GetDefaultOctaviaAPISpec()

		octaviaAPIName = types.NamespacedName{
			Namespace: namespace,
			Name:      name,
		}

		transportURLSecretName = types.NamespacedName{
			Namespace: namespace,
			Name:      RabbitmqSecretName,
		}
		spec["transportURLSecret"] = transportURLSecretName.Name
	})

	When("an OctaviaAPI instance is created", func() {
		BeforeEach(func() {
			DeferCleanup(th.DeleteInstance, CreateOctaviaAPI(octaviaAPIName, spec))
		})

		It("should have the Spec fields initialized", func() {
			octaviaAPI := GetOctaviaAPI((octaviaAPIName))
			Expect(octaviaAPI.Spec.DatabaseInstance).Should(Equal("test-octavia-db-instance"))
		})

		It("should have the Status fields initialized", func() {
			octaviaAPI := GetOctaviaAPI((octaviaAPIName))
			Expect(octaviaAPI.Status.ReadyCount).Should(Equal(int32(0)))
		})

		It("should have Waiting Conditions initialized as TransportUrl not created", func() {
			for _, cond := range []condition.Type{
				condition.InputReadyCondition,
			} {
				th.ExpectCondition(
					octaviaAPIName,
					ConditionGetterFunc(OctaviaAPIConditionGetter),
					cond,
					corev1.ConditionFalse,
				)
			}
		})

		It("should have a finalizer", func() {
			// the reconciler loop adds the finalizer so we have to wait for
			// it to run
			Eventually(func() []string {
				return GetOctaviaAPI(octaviaAPIName).Finalizers
			}, timeout, interval).Should(ContainElement("openstack.org/octaviaapi"))
		})

		It("should not create a secret", func() {
			secret := types.NamespacedName{
				Namespace: octaviaAPIName.Namespace,
				Name:      fmt.Sprintf("%s-%s", octaviaAPIName.Name, "config-data"),
			}
			th.AssertSecretDoesNotExist(secret)
		})
	})

	// Secret and Transport available
	When("a proper secret is provided and TransportURL is created", func() {
		BeforeEach(func() {
			DeferCleanup(th.DeleteInstance, CreateOctaviaAPI(octaviaAPIName, spec))
			DeferCleanup(k8sClient.Delete, ctx, CreateOctaviaSecret(namespace))
			DeferCleanup(k8sClient.Delete, ctx, CreateTransportURLSecret(transportURLSecretName))
		})

		It("should be in state of having the input ready", func() {
			th.ExpectCondition(
				octaviaAPIName,
				ConditionGetterFunc(OctaviaAPIConditionGetter),
				condition.InputReadyCondition,
				corev1.ConditionTrue,
			)
		})

		It("should not create a secret", func() {
			secret := types.NamespacedName{
				Namespace: octaviaAPIName.Namespace,
				Name:      fmt.Sprintf("%s-%s", octaviaAPIName.Name, "config-data"),
			}
			th.AssertSecretDoesNotExist(secret)
		})
	})

	// TLS Validation

	// Config
	When("config files are created", func() {
		var keystoneInternalEndpoint string
		var keystonePublicEndpoint string

		BeforeEach(func() {
			keystoneName := keystone.CreateKeystoneAPI(namespace)
			DeferCleanup(keystone.DeleteKeystoneAPI, keystoneName)
			keystoneInternalEndpoint = fmt.Sprintf("http://keystone-for-%s-internal", octaviaAPIName.Name)
			keystonePublicEndpoint = fmt.Sprintf("http://keystone-for-%s-public", octaviaAPIName.Name)
			SimulateKeystoneReady(keystoneName, keystonePublicEndpoint, keystoneInternalEndpoint)

			DeferCleanup(k8sClient.Delete, ctx, CreateOctaviaSecret(namespace))
			DeferCleanup(k8sClient.Delete, ctx, CreateTransportURLSecret(transportURLSecretName))

			spec["customServiceConfig"] = "[DEFAULT]\ndebug=True\n"
			DeferCleanup(th.DeleteInstance, CreateOctaviaAPI(octaviaAPIName, spec))

			mariaDBDatabaseName := mariadb.CreateMariaDBDatabase(namespace, octavia.DatabaseCRName, mariadbv1.MariaDBDatabaseSpec{})
			mariaDBDatabase := mariadb.GetMariaDBDatabase(mariaDBDatabaseName)
			DeferCleanup(k8sClient.Delete, ctx, mariaDBDatabase)

			octaviaAPI := GetOctaviaAPI(octaviaAPIName)
			apiMariaDBAccount, apiMariaDBSecret := mariadb.CreateMariaDBAccountAndSecret(
				types.NamespacedName{
					Namespace: namespace,
					Name:      octaviaAPI.Spec.DatabaseAccount,
				}, mariadbv1.MariaDBAccountSpec{})
			DeferCleanup(k8sClient.Delete, ctx, apiMariaDBAccount)
			DeferCleanup(k8sClient.Delete, ctx, apiMariaDBSecret)

			mariaDBDatabaseName = mariadb.CreateMariaDBDatabase(namespace, octavia.PersistenceDatabaseCRName, mariadbv1.MariaDBDatabaseSpec{})
			mariaDBDatabase = mariadb.GetMariaDBDatabase(mariaDBDatabaseName)
			DeferCleanup(k8sClient.Delete, ctx, mariaDBDatabase)

			apiMariaDBAccount, apiMariaDBSecret = mariadb.CreateMariaDBAccountAndSecret(
				types.NamespacedName{
					Namespace: namespace,
					Name:      octaviaAPI.Spec.PersistenceDatabaseAccount,
				}, mariadbv1.MariaDBAccountSpec{})
			DeferCleanup(k8sClient.Delete, ctx, apiMariaDBAccount)
			DeferCleanup(k8sClient.Delete, ctx, apiMariaDBSecret)

			ovndbCluster := ovn.CreateOVNDBCluster(namespace,
				ovnv1.OVNDBClusterSpec{
					OVNDBClusterSpecCore: ovnv1.OVNDBClusterSpecCore{
						DBType: ovnv1.NBDBType,
					}})
			ovndb := ovn.GetOVNDBCluster(ovndbCluster)
			DeferCleanup(k8sClient.Delete, ctx, ovndb)
			Eventually(func(g Gomega) {
				ovndb.Status.InternalDBAddress = OVNNBDBEndpoint
				g.Expect(k8sClient.Status().Update(ctx, ovndb)).To(Succeed())
			}).Should(Succeed())
			ovn.SimulateOVNDBClusterReady(ovndbCluster)

			ovndbCluster = ovn.CreateOVNDBCluster(namespace,
				ovnv1.OVNDBClusterSpec{
					OVNDBClusterSpecCore: ovnv1.OVNDBClusterSpecCore{
						DBType: ovnv1.SBDBType,
					}})
			ovndb = ovn.GetOVNDBCluster(ovndbCluster)
			DeferCleanup(k8sClient.Delete, ctx, ovndb)
			Eventually(func(g Gomega) {
				ovndb.Status.InternalDBAddress = OVNSBDBEndpoint
				g.Expect(k8sClient.Status().Update(ctx, ovndb)).To(Succeed())
			}).Should(Succeed())
			ovn.SimulateOVNDBClusterReady(ovndbCluster)
		})

		It("should set Service Config Ready Condition", func() {
			th.ExpectCondition(
				octaviaAPIName,
				ConditionGetterFunc(OctaviaAPIConditionGetter),
				condition.ServiceConfigReadyCondition,
				corev1.ConditionTrue,
			)
		})

		It("should create the octavia.conf file in a Secret", func() {
			configData := th.GetSecret(
				types.NamespacedName{
					Namespace: octaviaAPIName.Namespace,
					Name:      fmt.Sprintf("%s-config-data", octaviaAPIName.Name)})
			Expect(configData).ShouldNot(BeNil())
			conf := string(configData.Data["octavia.conf"])
			// TODO(gthiemonge) bind_host is currently hardcoded
			Expect(conf).ShouldNot(
				ContainSubstring("bind_host=\n"))

			instance := GetOctaviaAPI(octaviaAPIName)

			dbs := []struct {
				Name            string
				DatabaseAccount string
				Keyword         string
			}{
				{
					Name:            octavia.DatabaseName,
					DatabaseAccount: instance.Spec.DatabaseAccount,
					Keyword:         "connection",
				}, {
					Name:            octavia.PersistenceDatabaseName,
					DatabaseAccount: instance.Spec.PersistenceDatabaseAccount,
					Keyword:         "persistence_connection",
				},
			}

			for _, db := range dbs {
				databaseAccount := mariadb.GetMariaDBAccount(
					types.NamespacedName{
						Namespace: namespace,
						Name:      db.DatabaseAccount})
				databaseSecret := th.GetSecret(
					types.NamespacedName{
						Namespace: namespace,
						Name:      databaseAccount.Spec.Secret})

				Expect(conf).Should(
					ContainSubstring(
						fmt.Sprintf(
							"%s = mysql+pymysql://%s:%s@%s/%s?read_default_file=/etc/my.cnf",
							db.Keyword,
							databaseAccount.Spec.UserName,
							databaseSecret.Data[mariadbv1.DatabasePasswordSelector],
							instance.Spec.DatabaseHostname,
							db.Name)))
			}

			Expect(conf).Should(
				ContainSubstring(fmt.Sprintf(
					"www_authenticate_uri=%s\n", keystonePublicEndpoint)))
			// TBC: [keystone_authtoken].auth_url and [service_auth].auth_url differ?
			Expect(conf).Should(
				ContainSubstring(fmt.Sprintf(
					"auth_url=%s\n", keystoneInternalEndpoint)))
			Expect(conf).Should(
				ContainSubstring(fmt.Sprintf(
					"auth_url=%s/v3\n", keystoneInternalEndpoint)))
			Expect(conf).Should(
				ContainSubstring(fmt.Sprintf(
					"username=%s\n", instance.Spec.ServiceUser)))
			Expect(conf).Should(
				ContainSubstring(fmt.Sprintf(
					"ovn_nb_connection=%s\n", OVNNBDBEndpoint)))
			Expect(conf).Should(
				ContainSubstring(fmt.Sprintf(
					"ovn_sb_connection=%s\n", OVNSBDBEndpoint)))

			ospSecret := th.GetSecret(types.NamespacedName{
				Name:      SecretName,
				Namespace: namespace})
			Expect(conf).Should(
				ContainSubstring(fmt.Sprintf(
					"\npassword=%s\n", string(ospSecret.Data["OctaviaPassword"]))))

			transportURLSecret := th.GetSecret(transportURLSecretName)
			Expect(conf).Should(
				ContainSubstring(fmt.Sprintf(
					"transport_url=%s\n", string(transportURLSecret.Data["transport_url"]))))
		})

		It("should create a Secret with customServiceConfig input", func() {
			configData := th.GetSecret(
				types.NamespacedName{
					Namespace: octaviaAPIName.Namespace,
					Name:      fmt.Sprintf("%s-config-data", octaviaAPIName.Name)})
			Expect(configData).ShouldNot(BeNil())
			conf := string(configData.Data["custom.conf"])
			Expect(conf).Should(
				ContainSubstring("[DEFAULT]\ndebug=True\n"))
		})
	})

	When("A OctaviaAPI is created with HttpdCustomization.CustomConfigSecret", func() {
		var keystoneInternalEndpoint string
		var keystonePublicEndpoint string

		BeforeEach(func() {
			customServiceConfigSecretName := types.NamespacedName{Name: "foo", Namespace: namespace}
			customConfig := []byte(`CustomParam "foo"
CustomKeystonePublicURL "{{ .KeystonePublicURL }}"`)
			th.CreateSecret(
				customServiceConfigSecretName,
				map[string][]byte{
					"bar.conf": customConfig,
				},
			)

			keystoneName := keystone.CreateKeystoneAPI(namespace)
			DeferCleanup(keystone.DeleteKeystoneAPI, keystoneName)
			keystoneInternalEndpoint = fmt.Sprintf("http://keystone-for-%s-internal", octaviaAPIName.Name)
			keystonePublicEndpoint = fmt.Sprintf("http://keystone-for-%s-public", octaviaAPIName.Name)
			SimulateKeystoneReady(keystoneName, keystonePublicEndpoint, keystoneInternalEndpoint)

			DeferCleanup(k8sClient.Delete, ctx, CreateOctaviaSecret(namespace))
			DeferCleanup(k8sClient.Delete, ctx, CreateTransportURLSecret(transportURLSecretName))

			spec["httpdCustomization"] = map[string]interface{}{
				"customConfigSecret": customServiceConfigSecretName.Name,
			}

			DeferCleanup(th.DeleteInstance, CreateOctaviaAPI(octaviaAPIName, spec))

			mariaDBDatabaseName := mariadb.CreateMariaDBDatabase(namespace, octavia.DatabaseCRName, mariadbv1.MariaDBDatabaseSpec{})
			mariaDBDatabase := mariadb.GetMariaDBDatabase(mariaDBDatabaseName)
			DeferCleanup(k8sClient.Delete, ctx, mariaDBDatabase)

			octaviaAPI := GetOctaviaAPI(octaviaAPIName)
			apiMariaDBAccount, apiMariaDBSecret := mariadb.CreateMariaDBAccountAndSecret(
				types.NamespacedName{
					Namespace: namespace,
					Name:      octaviaAPI.Spec.DatabaseAccount,
				}, mariadbv1.MariaDBAccountSpec{})
			DeferCleanup(k8sClient.Delete, ctx, apiMariaDBAccount)
			DeferCleanup(k8sClient.Delete, ctx, apiMariaDBSecret)

			mariaDBDatabaseName = mariadb.CreateMariaDBDatabase(namespace, octavia.PersistenceDatabaseCRName, mariadbv1.MariaDBDatabaseSpec{})
			mariaDBDatabase = mariadb.GetMariaDBDatabase(mariaDBDatabaseName)
			DeferCleanup(k8sClient.Delete, ctx, mariaDBDatabase)

			apiMariaDBAccount, apiMariaDBSecret = mariadb.CreateMariaDBAccountAndSecret(
				types.NamespacedName{
					Namespace: namespace,
					Name:      octaviaAPI.Spec.PersistenceDatabaseAccount,
				}, mariadbv1.MariaDBAccountSpec{})
			DeferCleanup(k8sClient.Delete, ctx, apiMariaDBAccount)
			DeferCleanup(k8sClient.Delete, ctx, apiMariaDBSecret)

			ovndbCluster := ovn.CreateOVNDBCluster(namespace,
				ovnv1.OVNDBClusterSpec{
					OVNDBClusterSpecCore: ovnv1.OVNDBClusterSpecCore{
						DBType: ovnv1.NBDBType,
					}})
			ovndb := ovn.GetOVNDBCluster(ovndbCluster)
			DeferCleanup(k8sClient.Delete, ctx, ovndb)
			Eventually(func(g Gomega) {
				ovndb.Status.InternalDBAddress = OVNNBDBEndpoint
				g.Expect(k8sClient.Status().Update(ctx, ovndb)).To(Succeed())
			}).Should(Succeed())
			ovn.SimulateOVNDBClusterReady(ovndbCluster)

			ovndbCluster = ovn.CreateOVNDBCluster(namespace,
				ovnv1.OVNDBClusterSpec{
					OVNDBClusterSpecCore: ovnv1.OVNDBClusterSpecCore{
						DBType: ovnv1.SBDBType,
					}})
			ovndb = ovn.GetOVNDBCluster(ovndbCluster)
			DeferCleanup(k8sClient.Delete, ctx, ovndb)
			Eventually(func(g Gomega) {
				ovndb.Status.InternalDBAddress = OVNSBDBEndpoint
				g.Expect(k8sClient.Status().Update(ctx, ovndb)).To(Succeed())
			}).Should(Succeed())
			ovn.SimulateOVNDBClusterReady(ovndbCluster)
		})

		It("it renders the custom template and adds it to the placement-config-data secret", func() {
			scrt := th.GetSecret(
				types.NamespacedName{
					Namespace: octaviaAPIName.Namespace,
					Name:      fmt.Sprintf("%s-config-data", octaviaAPIName.Name)})
			Expect(scrt).ShouldNot(BeNil())
			Expect(scrt.Data).Should(HaveKey(common.TemplateParameters))
			configData := string(scrt.Data[common.TemplateParameters])
			Expect(configData).Should(ContainSubstring(fmt.Sprintf("KeystonePublicURL: %s", keystonePublicEndpoint)))

			for _, cfg := range []string{"httpd_custom_internal_bar.conf", "httpd_custom_public_bar.conf"} {
				Expect(scrt.Data).Should(HaveKey(cfg))
				configData := string(scrt.Data[cfg])
				Expect(configData).Should(ContainSubstring("CustomParam \"foo\""))
				Expect(configData).Should(ContainSubstring(fmt.Sprintf("CustomKeystonePublicURL \"%s\"", keystonePublicEndpoint)))
			}
		})
	})

	// NAD

	// Networks Annotation

	// Service

	// Keystone Service

	// Deployment
})
