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
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/quotas"

	api "github.com/openstack-k8s-operators/lib-common/modules/test/apis"
)

type NeutronAPIFixture struct {
	api.APIFixture
	Quotas       map[string]quotas.Quota
	DefaultQuota quotas.Quota
}

func (f *NeutronAPIFixture) registerHandler(handler api.Handler) {
	f.Server.AddHandler(f.URLBase+handler.Pattern, handler.Func)
}

func (f *NeutronAPIFixture) Setup() {
	f.registerHandler(api.Handler{Pattern: "/v2.0/quotas/", Func: f.quotasHandler})
}

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
	fmt.Fprint(w, string(bytes))
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
	f.APIFixture.Log.Info(fmt.Sprintf("Set quotas for %s to %+v\n", tenantID, q.Quota))
	f.Quotas[tenantID] = q.Quota

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(200)
	fmt.Fprint(w, string(bytes))
}

func NewNeutronAPIFixtureWithServer(log logr.Logger) *NeutronAPIFixture {
	server := &api.FakeAPIServer{}
	server.Setup(log)
	fixture := AddNeutronAPIFixture(log, server)
	fixture.OwnsServer = true
	return fixture
}

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
		Quotas: map[string]quotas.Quota{},
	}
	return fixture
}
