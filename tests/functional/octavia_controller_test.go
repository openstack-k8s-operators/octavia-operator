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
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/keypairs"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	. "github.com/onsi/ginkgo/v2" //revive:disable:dot-imports
	. "github.com/onsi/gomega"    //revive:disable:dot-imports
	"k8s.io/apimachinery/pkg/types"

	corev1 "k8s.io/api/core/v1"

	"github.com/openstack-k8s-operators/lib-common/modules/common/condition"

	//revive:disable-next-line:dot-imports
	. "github.com/openstack-k8s-operators/lib-common/modules/common/test/helpers"
	mariadbv1 "github.com/openstack-k8s-operators/mariadb-operator/api/v1beta1"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/octavia-operator/pkg/octavia"
)

func createAndSimulateKeystone(
	octaviaName types.NamespacedName,
) APIFixtures {
	apiFixtures := SetupAPIFixtures(logger)
	keystoneName := keystone.CreateKeystoneAPIWithFixture(namespace, apiFixtures.Keystone)
	DeferCleanup(keystone.DeleteKeystoneAPI, keystoneName)
	keystonePublicEndpoint := fmt.Sprintf("http://keystone-for-%s-public", octaviaName.Name)
	SimulateKeystoneReady(keystoneName, keystonePublicEndpoint, apiFixtures.Keystone.Endpoint())
	return apiFixtures
}

func createAndSimulateOctaviaSecrets(
	octaviaName types.NamespacedName,
) {
	DeferCleanup(k8sClient.Delete, ctx, CreateOctaviaSecret(octaviaName.Namespace))
	DeferCleanup(k8sClient.Delete, ctx, CreateOctaviaCaPassphraseSecret(octaviaName.Namespace, octaviaName.Name))
	SimulateOctaviaCertsSecret(octaviaName.Namespace, octaviaName.Name)
}

func createAndSimulateTransportURL(
	transportURLName types.NamespacedName,
	transportURLSecretName types.NamespacedName,
) {
	DeferCleanup(k8sClient.Delete, ctx, CreateTransportURL(transportURLName))
	DeferCleanup(k8sClient.Delete, ctx, CreateTransportURLSecret(transportURLSecretName))
	infra.SimulateTransportURLReady(transportURLName)
}

func createAndSimulateDB(spec map[string]interface{}) {
	DeferCleanup(
		mariadb.DeleteDBService,
		mariadb.CreateDBService(
			namespace,
			spec["databaseInstance"].(string),
			corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 3306}},
			},
		),
	)
	mariadb.CreateMariaDBAccount(namespace, spec["databaseAccount"].(string), mariadbv1.MariaDBAccountSpec{
		Secret:   "osp-secret",
		UserName: "octavia",
	})
	mariadb.CreateMariaDBAccount(namespace, spec["persistenceDatabaseAccount"].(string), mariadbv1.MariaDBAccountSpec{
		Secret:   "osp-secret",
		UserName: "octavia",
	})
	mariadb.CreateMariaDBDatabase(namespace, octavia.DatabaseCRName, mariadbv1.MariaDBDatabaseSpec{})
	mariadb.CreateMariaDBDatabase(namespace, octavia.PersistenceDatabaseCRName, mariadbv1.MariaDBDatabaseSpec{})
	mariadb.SimulateMariaDBAccountCompleted(types.NamespacedName{Namespace: namespace, Name: spec["databaseAccount"].(string)})
	mariadb.SimulateMariaDBDatabaseCompleted(types.NamespacedName{Namespace: namespace, Name: octavia.DatabaseCRName})
	mariadb.SimulateMariaDBAccountCompleted(types.NamespacedName{Namespace: namespace, Name: spec["persistenceDatabaseAccount"].(string)})
	mariadb.SimulateMariaDBDatabaseCompleted(types.NamespacedName{Namespace: namespace, Name: octavia.PersistenceDatabaseCRName})
}

func createAndSimulateOctaviaAPI(octaviaName types.NamespacedName) {
	octaviaAPIName := types.NamespacedName{
		Namespace: namespace,
		Name:      fmt.Sprintf("%s-api", octaviaName.Name),
	}
	DeferCleanup(th.DeleteInstance, CreateOctaviaAPI(octaviaAPIName, GetDefaultOctaviaAPISpec()))
	SimulateOctaviaAPIReady(octaviaAPIName)
}

var _ = Describe("Octavia controller", func() {
	var name string
	var spec map[string]interface{}
	var octaviaName types.NamespacedName
	var transportURLName types.NamespacedName
	var transportURLSecretName types.NamespacedName

	BeforeEach(func() {
		name = fmt.Sprintf("octavia-%s", uuid.New().String())
		spec = GetDefaultOctaviaSpec()

		octaviaName = types.NamespacedName{
			Namespace: namespace,
			Name:      name,
		}

		transportURLName = types.NamespacedName{
			Namespace: namespace,
			Name:      name + "-octavia-transport",
		}

		transportURLSecretName = types.NamespacedName{
			Namespace: namespace,
			Name:      RabbitmqSecretName,
		}
	})

	When("an Octavia instance is created", func() {
		BeforeEach(func() {
			DeferCleanup(th.DeleteInstance, CreateOctavia(octaviaName, spec))
		})

		It("should have the Spec fields initialized", func() {
			octavia := GetOctavia(octaviaName)
			Expect(octavia.Spec.DatabaseInstance).Should(Equal("test-octavia-db-instance"))
			Expect(octavia.Spec.Secret).Should(Equal(SecretName))
			Expect(octavia.Spec.TenantName).Should(Equal("service"))
		})

		It("should have the Status fields initialized", func() {
			octavia := GetOctavia(octaviaName)
			Expect(octavia.Status.DatabaseHostname).Should(Equal(""))
			Expect(octavia.Status.TransportURLSecret).Should(Equal(""))
			Expect(octavia.Status.OctaviaAPIReadyCount).Should(Equal(int32(0)))
			Expect(octavia.Status.OctaviaWorkerReadyCount).Should(Equal(int32(0)))
			Expect(octavia.Status.OctaviaHousekeepingReadyCount).Should(Equal(int32(0)))
			Expect(octavia.Status.OctaviaHealthManagerReadyCount).Should(Equal(int32(0)))
			Expect(octavia.Status.OctaviaRsyslogReadyCount).Should(Equal(int32(0)))
		})

		It("should have Unknown Conditions initialized as TransportUrl not created", func() {
			for _, cond := range []condition.Type{
				condition.RabbitMqTransportURLReadyCondition,
				condition.DBReadyCondition,
				condition.ServiceConfigReadyCondition,
			} {
				th.ExpectCondition(
					octaviaName,
					ConditionGetterFunc(OctaviaConditionGetter),
					cond,
					corev1.ConditionUnknown,
				)
			}
			// TODO(gthiemonge) InputReadyCondition is set to False while the controller is waiting for the transportURL to be created, this is probably not the correct behavior
			for _, cond := range []condition.Type{
				condition.InputReadyCondition,
				condition.ReadyCondition,
			} {
				th.ExpectCondition(
					octaviaName,
					ConditionGetterFunc(OctaviaConditionGetter),
					cond,
					corev1.ConditionFalse,
				)
			}
		})

		It("should have a finalizer", func() {
			// the reconciler loop adds the finalizer so we have to wait for
			// it to run
			Eventually(func() []string {
				return GetOctavia(octaviaName).Finalizers
			}, timeout, interval).Should(ContainElement("openstack.org/octavia"))
		})

		It("should not create a secret", func() {
			secret := types.NamespacedName{
				Namespace: octaviaName.Namespace,
				Name:      fmt.Sprintf("%s-%s", octaviaName.Name, "config-data"),
			}
			th.AssertSecretDoesNotExist(secret)
		})
	})

	// TransportURL
	When("a proper secret is provider, TransportURL is created", func() {
		BeforeEach(func() {
			DeferCleanup(th.DeleteInstance, CreateOctavia(octaviaName, spec))

			createAndSimulateOctaviaSecrets(octaviaName)
			createAndSimulateTransportURL(transportURLName, transportURLSecretName)
		})

		It("should be in state of having the input ready", func() {
			th.ExpectCondition(
				octaviaName,
				ConditionGetterFunc(OctaviaConditionGetter),
				condition.InputReadyCondition,
				corev1.ConditionTrue,
			)
		})

		It("should be in state of having the TransportURL ready", func() {
			th.ExpectCondition(
				octaviaName,
				ConditionGetterFunc(OctaviaConditionGetter),
				condition.RabbitMqTransportURLReadyCondition,
				corev1.ConditionTrue,
			)
		})

		It("should not create a secret", func() {
			secret := types.NamespacedName{
				Namespace: octaviaName.Namespace,
				Name:      fmt.Sprintf("%s-%s", octaviaName.Name, "config-data"),
			}
			th.AssertSecretDoesNotExist(secret)
		})
	})

	// Certs
	When("Certificates are created", func() {
		BeforeEach(func() {
			createAndSimulateKeystone(octaviaName)

			createAndSimulateOctaviaSecrets(octaviaName)
			createAndSimulateTransportURL(transportURLName, transportURLSecretName)

			DeferCleanup(th.DeleteInstance, CreateOctavia(octaviaName, spec))
		})

		It("should set the Certs Ready Condition to true", func() {
			th.ExpectCondition(
				octaviaName,
				ConditionGetterFunc(OctaviaConditionGetter),
				octaviav1.OctaviaAmphoraCertsReadyCondition,
				corev1.ConditionTrue,
			)
		})

		It("creates a secret that contains PEM files", func() {
			configData := th.GetSecret(
				types.NamespacedName{
					Namespace: octaviaName.Namespace,
					Name:      fmt.Sprintf("%s-certs-secret", octaviaName.Name)})
			Expect(configData).ShouldNot(BeNil())
			expectedKeys := []string{
				"server_ca.key.pem",
				"server_ca.cert.pem",
				"client_ca.cert.pem",
				"client.cert-and-key.pem"}
			for _, filename := range expectedKeys {
				Expect(configData.Data[filename]).ShouldNot(BeEmpty())
			}
		})
	})

	// Quotas
	When("Quotas are created", func() {
		var apiFixtures APIFixtures

		BeforeEach(func() {
			apiFixtures = createAndSimulateKeystone(octaviaName)

			createAndSimulateOctaviaSecrets(octaviaName)
			createAndSimulateTransportURL(transportURLName, transportURLSecretName)

			DeferCleanup(th.DeleteInstance, CreateOctavia(octaviaName, spec))
		})

		It("should set the Networking and Compute Quotas", func() {
			th.ExpectCondition(
				octaviaName,
				ConditionGetterFunc(OctaviaConditionGetter),
				octaviav1.OctaviaQuotasReadyCondition,
				corev1.ConditionTrue,
			)

			instance := GetOctavia(octaviaName)
			project := GetProject(instance.Spec.TenantName)

			quotaset := apiFixtures.Nova.QuotaSets[project.ID]
			Expect(quotaset.RAM).To(Equal(-1))
			Expect(quotaset.Cores).To(Equal(-1))
			Expect(quotaset.Instances).To(Equal(-1))
			Expect(quotaset.ServerGroups).To(Equal(-1))
			Expect(quotaset.ServerGroupMembers).To(Equal(-1))

			quota := apiFixtures.Neutron.Quotas[project.ID]
			Expect(quota.Port).To(Equal(-1))
			Expect(quota.SecurityGroup).To(Equal(-1))
			Expect(quota.SecurityGroupRule).To(Equal(-1))
		})
	})

	// NAD

	// DB
	When("DB is created", func() {
		BeforeEach(func() {
			createAndSimulateKeystone(octaviaName)

			createAndSimulateOctaviaSecrets(octaviaName)
			createAndSimulateTransportURL(transportURLName, transportURLSecretName)

			DeferCleanup(th.DeleteInstance, CreateOctavia(octaviaName, spec))

			DeferCleanup(
				mariadb.DeleteDBService,
				mariadb.CreateDBService(
					namespace,
					GetOctavia(octaviaName).Spec.DatabaseInstance,
					corev1.ServiceSpec{
						Ports: []corev1.ServicePort{{Port: 3306}},
					},
				),
			)
		})

		It("should set DBReady Condition and set DatabaseHostname Status", func() {
			mariadb.SimulateMariaDBAccountCompleted(types.NamespacedName{Namespace: namespace, Name: GetOctavia(octaviaName).Spec.DatabaseAccount})
			mariadb.SimulateMariaDBDatabaseCompleted(types.NamespacedName{Namespace: namespace, Name: octavia.DatabaseCRName})
			mariadb.SimulateMariaDBAccountCompleted(types.NamespacedName{Namespace: namespace, Name: GetOctavia(octaviaName).Spec.PersistenceDatabaseAccount})
			mariadb.SimulateMariaDBDatabaseCompleted(types.NamespacedName{Namespace: namespace, Name: octavia.PersistenceDatabaseCRName})
			th.SimulateJobSuccess(types.NamespacedName{Namespace: namespace, Name: octaviaName.Name + "-db-sync"})
			octavia := GetOctavia(octaviaName)
			hostname := "hostname-for-" + octavia.Spec.DatabaseInstance + "." + namespace + ".svc"
			Expect(octavia.Status.DatabaseHostname).To(Equal(hostname))
			th.ExpectCondition(
				octaviaName,
				ConditionGetterFunc(OctaviaConditionGetter),
				condition.DBReadyCondition,
				corev1.ConditionTrue,
			)
			th.ExpectCondition(
				octaviaName,
				ConditionGetterFunc(OctaviaConditionGetter),
				condition.DBSyncReadyCondition,
				corev1.ConditionFalse,
			)
		})
	})

	// Config
	When("The Config Secrets are created", func() {

		BeforeEach(func() {
			createAndSimulateKeystone(octaviaName)

			createAndSimulateOctaviaSecrets(octaviaName)
			createAndSimulateTransportURL(transportURLName, transportURLSecretName)

			createAndSimulateDB(spec)

			DeferCleanup(th.DeleteInstance, CreateOctavia(octaviaName, spec))

			th.SimulateJobSuccess(types.NamespacedName{Namespace: namespace, Name: octaviaName.Name + "-db-sync"})
		})

		It("should set Service Config Ready Condition", func() {
			th.ExpectCondition(
				octaviaName,
				ConditionGetterFunc(OctaviaConditionGetter),
				condition.ServiceConfigReadyCondition,
				corev1.ConditionTrue,
			)
		})

		It("should create the octavia.conf file in a Secret", func() {
			instance := GetOctavia(octaviaName)

			configData := th.GetSecret(
				types.NamespacedName{
					Namespace: octaviaName.Namespace,
					Name:      fmt.Sprintf("%s-config-data", octaviaName.Name)})
			Expect(configData).ShouldNot(BeNil())
			conf := string(configData.Data["octavia.conf"])
			Expect(conf).Should(
				ContainSubstring(
					fmt.Sprintf(
						"username=%s\n",
						instance.Spec.ServiceUser)))

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
							instance.Status.DatabaseHostname,
							db.Name)))
			}
		})

		It("should create a Secret for the scripts", func() {
			scriptData := th.GetSecret(
				types.NamespacedName{
					Namespace: octaviaName.Namespace,
					Name:      fmt.Sprintf("%s-scripts", octaviaName.Name)})
			Expect(scriptData).ShouldNot(BeNil())
		})
	})

	// Networks Annotation
	When("Network Annotation is created", func() {
		BeforeEach(func() {
			createAndSimulateKeystone(octaviaName)

			createAndSimulateOctaviaSecrets(octaviaName)
			createAndSimulateTransportURL(transportURLName, transportURLSecretName)

			createAndSimulateDB(spec)

			DeferCleanup(k8sClient.Delete, ctx, CreateNAD(types.NamespacedName{
				Name:      spec["octaviaNetworkAttachment"].(string),
				Namespace: namespace,
			}))

			DeferCleanup(th.DeleteInstance, CreateOctavia(octaviaName, spec))
		})

		It("should set the NetworkAttachementReady condition", func() {
			th.ExpectCondition(
				octaviaName,
				ConditionGetterFunc(OctaviaConditionGetter),
				condition.NetworkAttachmentsReadyCondition,
				corev1.ConditionTrue,
			)
		})
	})

	// API Deployment

	// Network Management
	When("The management network is created", func() {
		var apiFixtures APIFixtures

		BeforeEach(func() {
			apiFixtures = createAndSimulateKeystone(octaviaName)

			createAndSimulateOctaviaSecrets(octaviaName)
			createAndSimulateTransportURL(transportURLName, transportURLSecretName)

			createAndSimulateDB(spec)

			createAndSimulateOctaviaAPI(octaviaName)

			DeferCleanup(k8sClient.Delete, ctx, CreateNAD(types.NamespacedName{
				Name:      spec["octaviaNetworkAttachment"].(string),
				Namespace: namespace,
			}))

			DeferCleanup(k8sClient.Delete, ctx, CreateNode(types.NamespacedName{
				Namespace: namespace,
				Name:      "node1",
			}))

			DeferCleanup(th.DeleteInstance, CreateOctavia(octaviaName, spec))

			th.SimulateJobSuccess(types.NamespacedName{Namespace: namespace, Name: octaviaName.Name + "-db-sync"})
		})

		It("should create appropriate resources in Neutron", func() {
			// Replace with condition for LbMgmtNetwork when it's merged
			th.ExpectCondition(
				octaviaName,
				ConditionGetterFunc(OctaviaConditionGetter),
				condition.ExposeServiceReadyCondition,
				corev1.ConditionTrue,
			)

			instance := GetOctavia(octaviaName)
			tenant := GetProject(instance.Spec.TenantName)
			adminTenant := GetProject(octavia.AdminTenant)

			nadConfig := GetNADConfig(types.NamespacedName{
				Name:      instance.Spec.OctaviaNetworkAttachment,
				Namespace: namespace})

			// Networks
			expectedNetworks := map[string]networks.Network{
				octavia.LbMgmtNetName: {
					Description:           octavia.LbMgmtNetDescription,
					TenantID:              tenant.ID,
					AvailabilityZoneHints: instance.Spec.LbMgmtNetworks.AvailabilityZones,
				},
				octavia.LbProvNetName: {
					Description:           octavia.LbProvNetDescription,
					TenantID:              adminTenant.ID,
					AvailabilityZoneHints: instance.Spec.LbMgmtNetworks.AvailabilityZones,
				},
			}

			resultNetworks := map[string]networks.Network{}
			for _, network := range apiFixtures.Neutron.Networks {
				resultNetworks[network.Name] = network
			}
			Expect(resultNetworks).To(HaveLen(2))
			for name, expectedNetwork := range expectedNetworks {
				network := resultNetworks[name]
				Expect(network).ToNot(Equal(networks.Network{}), "Network %s doesn't appear to exist", name)
				Expect(network.Description).To(Equal(expectedNetwork.Description))
				Expect(network.TenantID).To(Equal(expectedNetwork.TenantID))
				Expect(network.AvailabilityZoneHints).To(Equal(expectedNetwork.AvailabilityZoneHints))
			}

			lbMgmtPortAddress := ""
			lbMgmtPortID := ""
			for _, port := range apiFixtures.Neutron.Ports {
				if port.Name == octavia.LbMgmtRouterPortName {
					lbMgmtPortAddress = port.FixedIPs[0].IPAddress
					lbMgmtPortID = port.ID
					break
				}
			}
			// Subnets
			expectedSubnets := map[string]subnets.Subnet{
				octavia.LbMgmtSubnetName: {
					Description: octavia.LbMgmtSubnetDescription,
					TenantID:    tenant.ID,
					NetworkID:   resultNetworks[octavia.LbMgmtNetName].ID,
					CIDR:        nadConfig.IPAM.Routes[0].Destination.String(),
					HostRoutes: []subnets.HostRoute{{
						DestinationCIDR: nadConfig.IPAM.CIDR.String(),
						NextHop:         lbMgmtPortAddress,
					}},
				},
				octavia.LbProvSubnetName: {
					Description: octavia.LbProvSubnetDescription,
					TenantID:    adminTenant.ID,
					NetworkID:   resultNetworks[octavia.LbProvNetName].ID,
					CIDR:        nadConfig.IPAM.CIDR.String(),
				},
			}

			resultSubnets := map[string]subnets.Subnet{}
			for _, subnet := range apiFixtures.Neutron.Subnets {
				resultSubnets[subnet.Name] = subnet
			}
			Expect(resultSubnets).To(HaveLen(2))
			for name, expectedSubnet := range expectedSubnets {
				subnet := resultSubnets[name]
				Expect(subnet).ToNot(Equal(subnets.Subnet{}), "Subnet %s doesn't appear to exist", name)
				Expect(subnet.Description).To(Equal(expectedSubnet.Description))
				Expect(subnet.TenantID).To(Equal(expectedSubnet.TenantID))
				Expect(subnet.NetworkID).To(Equal(expectedSubnet.NetworkID))
				Expect(subnet.CIDR).To(Equal(expectedSubnet.CIDR))
				Expect(subnet.HostRoutes).To(Equal(expectedSubnet.HostRoutes))
			}

			// Routers
			expectedRouters := map[string]routers.Router{
				octavia.LbRouterName: {
					GatewayInfo: routers.GatewayInfo{
						NetworkID: resultNetworks[octavia.LbProvNetName].ID,
						ExternalFixedIPs: []routers.ExternalFixedIP{
							{
								SubnetID: resultSubnets[octavia.LbProvSubnetName].ID,
							},
						},
					},
					AvailabilityZoneHints: instance.Spec.LbMgmtNetworks.AvailabilityZones,
				},
			}

			resultRouters := map[string]routers.Router{}
			for _, router := range apiFixtures.Neutron.Routers {
				resultRouters[router.Name] = router
			}
			Expect(resultRouters).To(HaveLen(1))
			for name, expectedRouter := range expectedRouters {
				router := resultRouters[name]
				Expect(router).ToNot(Equal(routers.Router{}), "Router %s doesn't appear to exist", name)
				Expect(router.GatewayInfo.NetworkID).To(Equal(expectedRouter.GatewayInfo.NetworkID))
				Expect(router.GatewayInfo.ExternalFixedIPs[0].SubnetID).To(Equal(expectedRouter.GatewayInfo.ExternalFixedIPs[0].SubnetID))
				Expect(router.AvailabilityZoneHints).To(Equal(expectedRouter.AvailabilityZoneHints))
			}

			expectedInterfaces := map[string]routers.InterfaceInfo{
				fmt.Sprintf("%s:%s", resultRouters[octavia.LbRouterName].ID, resultSubnets[octavia.LbMgmtSubnetName].ID): {
					SubnetID: resultSubnets[octavia.LbMgmtSubnetName].ID,
					PortID:   lbMgmtPortID,
				},
			}
			for id, expectedInterfaces := range expectedInterfaces {
				iface := apiFixtures.Neutron.InterfaceInfos[id]
				Expect(iface).ToNot(Equal(routers.InterfaceInfo{}), "Interface %s doesn't appear to exist", id)
				Expect(iface.SubnetID).To(Equal(expectedInterfaces.SubnetID))
				Expect(iface.PortID).To(Equal(expectedInterfaces.PortID))
			}
		})
	})

	// Predictable IPs

	// Amphora Controller Daemonsets

	// Rsyslog Daemonset

	// Amp SSH Config
	When("The Amphora SSH config map is created", func() {
		var apiFixtures APIFixtures

		BeforeEach(func() {
			apiFixtures = createAndSimulateKeystone(octaviaName)

			createAndSimulateOctaviaSecrets(octaviaName)
			createAndSimulateTransportURL(transportURLName, transportURLSecretName)

			createAndSimulateDB(spec)

			createAndSimulateOctaviaAPI(octaviaName)

			DeferCleanup(k8sClient.Delete, ctx, CreateNAD(types.NamespacedName{
				Name:      spec["octaviaNetworkAttachment"].(string),
				Namespace: namespace,
			}))

			DeferCleanup(k8sClient.Delete, ctx, CreateNode(types.NamespacedName{
				Namespace: namespace,
				Name:      "node1",
			}))

			DeferCleanup(th.DeleteInstance, CreateOctavia(octaviaName, spec))

			th.SimulateJobSuccess(types.NamespacedName{Namespace: namespace, Name: octaviaName.Name + "-db-sync"})
		})

		It("should set OctaviaAmphoraSSHReady condition", func() {
			th.ExpectCondition(
				octaviaName,
				ConditionGetterFunc(OctaviaConditionGetter),
				octaviav1.OctaviaAmphoraSSHReadyCondition,
				corev1.ConditionTrue,
			)
		})

		It("should upload a new keypair", func() {
			keyPairs := apiFixtures.Nova.KeyPairs
			Expect(keyPairs[octavia.NovaKeyPairName]).ShouldNot(Equal(keypairs.KeyPair{}))
		})

		It("should set a key in the config map", func() {
			instance := GetOctavia(octaviaName)
			configMap := th.GetConfigMap(types.NamespacedName{
				Name:      instance.Spec.LoadBalancerSSHPubKey,
				Namespace: namespace})
			Expect(configMap).ShouldNot(BeNil())
			Expect(configMap.Data["key"]).Should(
				ContainSubstring("ecdsa-"))
		})
	})

	When("The Amphora SSH config map and the keypair already exist", func() {
		var apiFixtures APIFixtures

		BeforeEach(func() {
			apiFixtures = createAndSimulateKeystone(octaviaName)
			apiFixtures.Nova.KeyPairs = map[string]keypairs.KeyPair{
				"octavia-ssh-keypair": {
					Name:      "octavia-ssh-keypair",
					PublicKey: "foobar",
					UserID:    apiFixtures.Keystone.Users["octavia"].ID,
				}}

			createAndSimulateOctaviaSecrets(octaviaName)
			createAndSimulateTransportURL(transportURLName, transportURLSecretName)

			createAndSimulateDB(spec)

			createAndSimulateOctaviaAPI(octaviaName)

			DeferCleanup(k8sClient.Delete, ctx, CreateNAD(types.NamespacedName{
				Name:      spec["octaviaNetworkAttachment"].(string),
				Namespace: namespace,
			}))

			DeferCleanup(k8sClient.Delete, ctx, CreateNode(types.NamespacedName{
				Namespace: namespace,
				Name:      "node1",
			}))

			DeferCleanup(th.DeleteInstance, CreateSSHPubKey())

			DeferCleanup(th.DeleteInstance, CreateOctavia(octaviaName, spec))

			th.SimulateJobSuccess(types.NamespacedName{Namespace: namespace, Name: octaviaName.Name + "-db-sync"})
		})

		// PENDING https://issues.redhat.com/browse/OSPRH-10543
		PIt("should not update the keypair", func() {
			keyPairs := apiFixtures.Nova.KeyPairs
			Expect(keyPairs["octavia-ssh-keypair"].PublicKey).Should(Equal("foobar"))
		})
	})

	// Amphora Image
})
