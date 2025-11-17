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
	"io"
	"net/http"
	"strings"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/external"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/quotas"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/rbacpolicies"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/subnets"

	api "github.com/openstack-k8s-operators/lib-common/modules/test/apis"
	"github.com/openstack-k8s-operators/octavia-operator/internal/octavia"
)

// Network represents a neutron network with external extension for testing
type Network struct {
	networks.Network
	external.NetworkExternalExt
}

// NeutronAPIFixture provides a test fixture for mocking Neutron API responses
type NeutronAPIFixture struct {
	api.APIFixture
	Quotas         map[string]quotas.Quota
	DefaultQuota   quotas.Quota
	Networks       map[string]Network
	Subnets        map[string]subnets.Subnet
	SecGroups      map[string]groups.SecGroup
	Ports          map[string]ports.Port
	Routers        map[string]routers.Router
	InterfaceInfos map[string]routers.InterfaceInfo
	RBACs          map[string]rbacpolicies.RBACPolicy
}

func (f *NeutronAPIFixture) registerHandler(handler api.Handler) {
	f.Server.AddHandler(f.URLBase+handler.Pattern, handler.Func)
}

func (f *NeutronAPIFixture) versionHandler(w http.ResponseWriter, r *http.Request) {
	f.LogRequest(r)
	if r.Method != "GET" {
		f.UnexpectedRequest(w, r)
		return
	}

	// Return network API version information
	response := map[string]interface{}{
		"versions": []map[string]interface{}{
			{
				"id":     "v2.0",
				"status": "CURRENT",
				"links": []map[string]string{
					{
						"href": f.Server.Endpoint() + f.URLBase + "/v2.0",
						"rel":  "self",
					},
				},
			},
		},
	}

	bytes, err := json.Marshal(response)
	if err != nil {
		f.InternalError(err, "Error during marshalling response", w, r)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = fmt.Fprint(w, string(bytes))
}

// Setup initializes the NeutronAPIFixture with API handlers and test data
func (f *NeutronAPIFixture) Setup() {
	f.registerHandler(api.Handler{Pattern: "/", Func: f.versionHandler})
	f.registerHandler(api.Handler{Pattern: "/v2.0/networks/", Func: f.networkHandler})
	f.registerHandler(api.Handler{Pattern: "/v2.0/networks", Func: f.networkHandler})
	f.registerHandler(api.Handler{Pattern: "/v2.0/subnets/", Func: f.subnetHandler})
	f.registerHandler(api.Handler{Pattern: "/v2.0/subnets", Func: f.subnetHandler})
	f.registerHandler(api.Handler{Pattern: "/v2.0/security-groups/", Func: f.securityGroupHandler})
	f.registerHandler(api.Handler{Pattern: "/v2.0/security-groups", Func: f.securityGroupHandler})
	f.registerHandler(api.Handler{Pattern: "/v2.0/ports/", Func: f.portHandler})
	f.registerHandler(api.Handler{Pattern: "/v2.0/ports", Func: f.portHandler})
	f.registerHandler(api.Handler{Pattern: "/v2.0/routers/", Func: f.routerHandler})
	f.registerHandler(api.Handler{Pattern: "/v2.0/routers", Func: f.routerHandler})
	f.registerHandler(api.Handler{Pattern: "/v2.0/quotas/", Func: f.quotasHandler})
	f.registerHandler(api.Handler{Pattern: "/v2.0/rbac-policies/", Func: f.rbacHandler})
	f.registerHandler(api.Handler{Pattern: "/v2.0/rbac-policies", Func: f.rbacHandler})
}

// Network
func (f *NeutronAPIFixture) networkHandler(w http.ResponseWriter, r *http.Request) {
	f.LogRequest(r)
	switch r.Method {
	case "GET":
		f.getNetwork(w, r)
	case "POST":
		f.postNetwork(w, r)
	default:
		f.UnexpectedRequest(w, r)
		return
	}
}

func (f *NeutronAPIFixture) getNetwork(w http.ResponseWriter, r *http.Request) {
	items := strings.Split(r.URL.Path, "/")
	if len(items) == 4 {
		var n struct {
			Networks []Network `json:"networks"`
		}
		n.Networks = []Network{}
		query := r.URL.Query()
		name := query["name"]
		tenantID := query["tenant_id"]
		for _, network := range f.Networks {
			if len(name) > 0 && name[0] != network.Name {
				continue
			}
			if len(tenantID) > 0 && tenantID[0] != network.TenantID {
				continue
			}
			n.Networks = append(n.Networks, network)
		}
		bytes, err := json.Marshal(&n)
		if err != nil {
			f.InternalError(err, "Error during marshalling response", w, r)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, string(bytes))
	}
}

func (f *NeutronAPIFixture) postNetwork(w http.ResponseWriter, r *http.Request) {
	bytes, err := io.ReadAll(r.Body)
	if err != nil {
		f.InternalError(err, "Error reading request body", w, r)
		return
	}

	var n struct {
		Network Network `json:"network"`
	}

	err = json.Unmarshal(bytes, &n)
	if err != nil {
		f.InternalError(err, "Error during marshalling response", w, r)
		return
	}

	networkID := uuid.New().String()
	n.Network.ID = networkID
	f.Networks[networkID] = n.Network

	// Note(gthiemonge) it seems that router:external is not correctly
	// unmarshall by the go code, let's assume that only octavia-provider-net is
	// an external network
	if n.Network.Name == octavia.LbProvNetName {
		rbacID := uuid.New().String()
		f.RBACs[rbacID] = rbacpolicies.RBACPolicy{
			ID:           rbacID,
			ObjectID:     networkID,
			TenantID:     n.Network.TenantID,
			TargetTenant: "*",
		}
	}

	bytes, err = json.Marshal(&n)
	if err != nil {
		f.InternalError(err, "Error during marshalling response", w, r)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(201)
	_, _ = fmt.Fprint(w, string(bytes))
}

// Subnet
func (f *NeutronAPIFixture) subnetHandler(w http.ResponseWriter, r *http.Request) {
	f.LogRequest(r)
	switch r.Method {
	case "GET":
		f.getSubnet(w, r)
	case "POST":
		f.postSubnet(w, r)
	case "PUT":
		f.putSubnet(w, r)
	default:
		f.UnexpectedRequest(w, r)
		return
	}
}

func (f *NeutronAPIFixture) getSubnet(w http.ResponseWriter, r *http.Request) {
	items := strings.Split(r.URL.Path, "/")
	if len(items) == 4 {
		var n struct {
			Subnets []subnets.Subnet `json:"subnets"`
		}
		n.Subnets = []subnets.Subnet{}
		query := r.URL.Query()
		name := query["name"]
		tenantID := query["tenant_id"]
		networkID := query["network_id"]
		ipVersion := query["ip_version"]
		for _, subnet := range f.Subnets {
			if len(name) > 0 && name[0] != subnet.Name {
				continue
			}
			if len(tenantID) > 0 && tenantID[0] != subnet.TenantID {
				continue
			}
			if len(networkID) > 0 && networkID[0] != subnet.NetworkID {
				continue
			}
			if len(ipVersion) > 0 && ipVersion[0] != fmt.Sprintf("%d", subnet.IPVersion) {
				continue
			}
			n.Subnets = append(n.Subnets, subnet)
		}
		bytes, err := json.Marshal(&n)
		if err != nil {
			f.InternalError(err, "Error during marshalling response", w, r)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, string(bytes))
	}
}

func (f *NeutronAPIFixture) postSubnet(w http.ResponseWriter, r *http.Request) {
	bytes, err := io.ReadAll(r.Body)
	if err != nil {
		f.InternalError(err, "Error reading request body", w, r)
		return
	}

	var n struct {
		Subnet subnets.Subnet `json:"subnet"`
	}

	err = json.Unmarshal(bytes, &n)
	if err != nil {
		f.InternalError(err, "Error during marshalling response", w, r)
		return
	}

	networkID := n.Subnet.NetworkID
	subnetID := uuid.New().String()
	n.Subnet.ID = subnetID
	f.Subnets[subnetID] = n.Subnet

	network := f.Networks[networkID]
	network.Subnets = append(network.Subnets, subnetID)
	f.Networks[networkID] = network

	bytes, err = json.Marshal(&n)
	if err != nil {
		f.InternalError(err, "Error during marshalling response", w, r)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(201)
	_, _ = fmt.Fprint(w, string(bytes))
}

func (f *NeutronAPIFixture) putSubnet(w http.ResponseWriter, r *http.Request) {
	items := strings.Split(r.URL.Path, "/")
	subnetID := items[4]

	bytes, err := io.ReadAll(r.Body)
	if err != nil {
		f.InternalError(err, "Error reading request body", w, r)
		return
	}

	var n struct {
		Subnet subnets.Subnet `json:"subnet"`
	}

	err = json.Unmarshal(bytes, &n)
	if err != nil {
		f.InternalError(err, "Error during marshalling response", w, r)
		return
	}

	subnet := f.Subnets[subnetID]
	if len(n.Subnet.HostRoutes) > 0 {
		subnet.HostRoutes = n.Subnet.HostRoutes
	}
	f.Subnets[subnetID] = subnet

	bytes, err = json.Marshal(&n)
	if err != nil {
		f.InternalError(err, "Error during marshalling response", w, r)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(201)
	_, _ = fmt.Fprint(w, string(bytes))
}

// SecGroup
func (f *NeutronAPIFixture) securityGroupHandler(w http.ResponseWriter, r *http.Request) {
	f.LogRequest(r)
	switch r.Method {
	case "GET":
		f.getSecurityGroup(w, r)
	case "POST":
		f.postSecurityGroup(w, r)
	default:
		f.UnexpectedRequest(w, r)
		return
	}
}

func (f *NeutronAPIFixture) getSecurityGroup(w http.ResponseWriter, r *http.Request) {
	items := strings.Split(r.URL.Path, "/")
	if len(items) == 4 {
		var n struct {
			SecGroups []groups.SecGroup `json:"security_groups"`
		}
		n.SecGroups = []groups.SecGroup{}
		query := r.URL.Query()
		name := query["name"]
		tenantID := query["tenant_id"]
		for _, securityGroup := range f.SecGroups {
			if len(name) > 0 && name[0] != securityGroup.Name {
				continue
			}
			if len(tenantID) > 0 && tenantID[0] != securityGroup.TenantID {
				continue
			}
			n.SecGroups = append(n.SecGroups, securityGroup)
		}
		bytes, err := json.Marshal(&n)
		if err != nil {
			f.InternalError(err, "Error during marshalling response", w, r)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, string(bytes))
	}
}

func (f *NeutronAPIFixture) postSecurityGroup(w http.ResponseWriter, r *http.Request) {
	bytes, err := io.ReadAll(r.Body)
	if err != nil {
		f.InternalError(err, "Error reading request body", w, r)
		return
	}

	var n struct {
		SecGroup groups.SecGroup `json:"security_group"`
	}

	err = json.Unmarshal(bytes, &n)
	if err != nil {
		f.InternalError(err, "Error during marshalling response", w, r)
		return
	}

	securityGroupID := uuid.New().String()
	n.SecGroup.ID = securityGroupID
	f.SecGroups[securityGroupID] = n.SecGroup

	bytes, err = json.Marshal(&n)
	if err != nil {
		f.InternalError(err, "Error during marshalling response", w, r)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(201)
	_, _ = fmt.Fprint(w, string(bytes))
}

// Port
func (f *NeutronAPIFixture) portHandler(w http.ResponseWriter, r *http.Request) {
	f.LogRequest(r)
	switch r.Method {
	case "GET":
		f.getPort(w, r)
	case "POST":
		f.postPort(w, r)
	default:
		f.UnexpectedRequest(w, r)
		return
	}
}

func (f *NeutronAPIFixture) getPort(w http.ResponseWriter, r *http.Request) {
	items := strings.Split(r.URL.Path, "/")
	if len(items) == 4 {
		var n struct {
			Ports []ports.Port `json:"ports"`
		}
		n.Ports = []ports.Port{}
		query := r.URL.Query()
		name := query["name"]
		tenantID := query["tenant_id"]
		networkID := query["network_id"]
		for _, port := range f.Ports {
			if len(name) > 0 && name[0] != port.Name {
				continue
			}
			if len(tenantID) > 0 && tenantID[0] != port.TenantID {
				continue
			}
			if len(networkID) > 0 && networkID[0] != port.NetworkID {
				continue
			}
			n.Ports = append(n.Ports, port)
		}
		bytes, err := json.Marshal(&n)
		if err != nil {
			f.InternalError(err, "Error during marshalling response", w, r)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, string(bytes))
	}
}

func (f *NeutronAPIFixture) postPort(w http.ResponseWriter, r *http.Request) {
	bytes, err := io.ReadAll(r.Body)
	if err != nil {
		f.InternalError(err, "Error reading request body", w, r)
		return
	}

	var n struct {
		Port ports.Port `json:"port"`
	}

	err = json.Unmarshal(bytes, &n)
	if err != nil {
		f.InternalError(err, "Error during marshalling response", w, r)
		return
	}

	network := f.Networks[n.Port.NetworkID]

	portID := uuid.New().String()
	n.Port.ID = portID
	n.Port.FixedIPs = []ports.IP{
		{
			IPAddress: fmt.Sprintf("%s.ipaddress", portID),
			SubnetID:  network.Subnets[0],
		},
	}
	f.Ports[portID] = n.Port

	bytes, err = json.Marshal(&n)
	if err != nil {
		f.InternalError(err, "Error during marshalling response", w, r)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(201)
	_, _ = fmt.Fprint(w, string(bytes))
}

// Router
func (f *NeutronAPIFixture) routerHandler(w http.ResponseWriter, r *http.Request) {
	f.LogRequest(r)
	switch r.Method {
	case "GET":
		f.getRouter(w, r)
	case "POST":
		f.postRouter(w, r)
	case "PUT":
		f.putRouter(w, r)
	default:
		f.UnexpectedRequest(w, r)
		return
	}
}

func (f *NeutronAPIFixture) getRouter(w http.ResponseWriter, r *http.Request) {
	items := strings.Split(r.URL.Path, "/")
	if len(items) == 4 {
		var n struct {
			Routers []routers.Router `json:"routers"`
		}
		n.Routers = []routers.Router{}
		query := r.URL.Query()
		name := query["name"]
		tenantID := query["tenant_id"]
		for _, router := range f.Routers {
			if len(name) > 0 && name[0] != router.Name {
				continue
			}
			if len(tenantID) > 0 && tenantID[0] != router.TenantID {
				continue
			}
			n.Routers = append(n.Routers, router)
		}
		bytes, err := json.Marshal(&n)
		if err != nil {
			f.InternalError(err, "Error during marshalling response", w, r)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, string(bytes))
	}
}

func (f *NeutronAPIFixture) postRouter(w http.ResponseWriter, r *http.Request) {
	bytes, err := io.ReadAll(r.Body)
	if err != nil {
		f.InternalError(err, "Error reading request body", w, r)
		return
	}

	var n struct {
		Router routers.Router `json:"router"`
	}

	err = json.Unmarshal(bytes, &n)
	if err != nil {
		f.InternalError(err, "Error during marshalling response", w, r)
		return
	}

	routerID := uuid.New().String()
	n.Router.ID = routerID
	f.Routers[routerID] = n.Router

	bytes, err = json.Marshal(&n)
	if err != nil {
		f.InternalError(err, "Error during marshalling response", w, r)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(201)
	_, _ = fmt.Fprint(w, string(bytes))
}

func (f *NeutronAPIFixture) putRouter(w http.ResponseWriter, r *http.Request) {
	items := strings.Split(r.URL.Path, "/")
	routerID := items[4]
	action := items[5]

	if action == "add_router_interface" {
		bytes, err := io.ReadAll(r.Body)
		if err != nil {
			f.InternalError(err, "Error reading request body", w, r)
			return
		}

		var n struct {
			SubnetID string `json:"subnet_id"`
			PortID   string `json:"port_id"`
		}

		err = json.Unmarshal(bytes, &n)
		if err != nil {
			f.InternalError(err, "Error during marshalling response", w, r)
			return
		}

		var subnetID string
		if n.SubnetID == "" {
			subnetID = f.Ports[n.PortID].FixedIPs[0].SubnetID
		} else {
			subnetID = n.SubnetID
		}
		f.InterfaceInfos[fmt.Sprintf("%s:%s", routerID, subnetID)] = routers.InterfaceInfo{
			SubnetID: subnetID,
			PortID:   n.PortID,
		}

		bytes, err = json.Marshal(&n)
		if err != nil {
			f.InternalError(err, "Error during marshalling response", w, r)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, string(bytes))
	}
}

// Quota
func (f *NeutronAPIFixture) quotasHandler(w http.ResponseWriter, r *http.Request) {
	f.LogRequest(r)
	switch r.Method {
	case "GET":
		f.getQuotas(w, r)
	case "PUT":
		f.putQuotas(w, r)
	default:
		f.UnexpectedRequest(w, r)
		return
	}
}

func (f *NeutronAPIFixture) getQuotas(w http.ResponseWriter, r *http.Request) {
	items := strings.Split(r.URL.Path, "/")
	tenantID := items[len(items)-1]

	var q struct {
		Quota quotas.Quota `json:"quota"`
	}
	if quotaset, ok := f.Quotas[tenantID]; ok {
		q.Quota = quotaset
	} else {
		q.Quota = f.DefaultQuota
	}
	bytes, err := json.Marshal(&q)
	if err != nil {
		f.InternalError(err, "Error during marshalling response", w, r)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = fmt.Fprint(w, string(bytes))
}

func (f *NeutronAPIFixture) putQuotas(w http.ResponseWriter, r *http.Request) {
	items := strings.Split(r.URL.Path, "/")
	tenantID := items[len(items)-1]

	bytes, err := io.ReadAll(r.Body)
	if err != nil {
		f.InternalError(err, "Error reading request body", w, r)
		return
	}
	var q struct {
		Quota quotas.Quota `json:"quota"`
	}
	err = json.Unmarshal(bytes, &q)
	if err != nil {
		f.InternalError(err, "Error during unmarshalling request", w, r)
		return
	}
	f.Log.Info(fmt.Sprintf("Set quotas for %s to %+v\n", tenantID, q.Quota))
	f.Quotas[tenantID] = q.Quota

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = fmt.Fprint(w, string(bytes))
}

func (f *NeutronAPIFixture) rbacHandler(w http.ResponseWriter, r *http.Request) {
	f.LogRequest(r)
	switch r.Method {
	case "GET":
		f.getRBAC(w, r)
	case "PUT":
		f.putRBAC(w, r)
	default:
		f.UnexpectedRequest(w, r)
		return
	}
}

func (f *NeutronAPIFixture) getRBAC(w http.ResponseWriter, r *http.Request) {
	items := strings.Split(r.URL.Path, "/")
	if len(items) == 4 {
		var resp struct {
			RBACs []rbacpolicies.RBACPolicy `json:"rbac_policies"`
		}
		resp.RBACs = []rbacpolicies.RBACPolicy{}
		query := r.URL.Query()
		objectID := query["object_id"][0]
		tenantID := query["tenant_id"][0]
		targetTenant := query["target_tenant"][0]
		for _, rbac := range f.RBACs {
			if objectID == rbac.ObjectID &&
				tenantID == rbac.TenantID &&
				targetTenant == rbac.TargetTenant {
				resp.RBACs = append(resp.RBACs, rbac)
			}
		}
		bytes, err := json.Marshal(&resp)
		if err != nil {
			f.InternalError(err, "Error during marshalling response", w, r)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, string(bytes))
	}
}

func (f *NeutronAPIFixture) putRBAC(w http.ResponseWriter, r *http.Request) {
	items := strings.Split(r.URL.Path, "/")
	rbacID := items[len(items)-1]

	bytes, err := io.ReadAll(r.Body)
	if err != nil {
		f.InternalError(err, "Error reading request body", w, r)
		return
	}
	var rbac struct {
		RBAC rbacpolicies.RBACPolicy `json:"rbac_policy"`
	}
	err = json.Unmarshal(bytes, &rbac)
	if err != nil {
		f.InternalError(err, "Error during unmarshalling request", w, r)
		return
	}
	updatedRBAC := f.RBACs[rbacID]
	if rbac.RBAC.TargetTenant != "" {
		updatedRBAC.TargetTenant = rbac.RBAC.TargetTenant
	}
	f.Log.Info(fmt.Sprintf("Set RBAC %s to %+v\n", rbacID, updatedRBAC))
	f.RBACs[rbacID] = updatedRBAC

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = fmt.Fprint(w, string(bytes))
}

// NewNeutronAPIFixtureWithServer creates a new NeutronAPIFixture with its own test server
func NewNeutronAPIFixtureWithServer(log logr.Logger) *NeutronAPIFixture {
	server := &api.FakeAPIServer{}
	server.Setup(log)
	fixture := AddNeutronAPIFixture(log, server)
	fixture.OwnsServer = true
	return fixture
}

// AddNeutronAPIFixture adds a NeutronAPIFixture to an existing test server
func AddNeutronAPIFixture(log logr.Logger, server *api.FakeAPIServer) *NeutronAPIFixture {
	fixture := &NeutronAPIFixture{
		APIFixture: api.APIFixture{
			Server:     server,
			Log:        log,
			URLBase:    "/network",
			OwnsServer: false,
		},
		DefaultQuota: quotas.Quota{
			Port:              10,
			SecurityGroup:     10,
			SecurityGroupRule: 10,
		},
		Quotas:         map[string]quotas.Quota{},
		Networks:       map[string]Network{},
		Subnets:        map[string]subnets.Subnet{},
		SecGroups:      map[string]groups.SecGroup{},
		Ports:          map[string]ports.Port{},
		Routers:        map[string]routers.Router{},
		InterfaceInfos: map[string]routers.InterfaceInfo{},
		RBACs:          map[string]rbacpolicies.RBACPolicy{},
	}
	return fixture
}
