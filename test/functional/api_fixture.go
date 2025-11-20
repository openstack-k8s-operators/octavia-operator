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

// Package functional_test provides functional testing utilities and fixtures for Octavia operator
package functional_test

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-logr/logr"
	"github.com/google/uuid"

	. "github.com/onsi/ginkgo/v2" //nolint:staticcheck,revive // ST1001,dot-imports: dot imports are standard practice for Ginkgo tests

	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/projects"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/users"
	keystone_helpers "github.com/openstack-k8s-operators/keystone-operator/api/test/helpers"

	api "github.com/openstack-k8s-operators/lib-common/modules/test/apis"
)

var keystoneProjects = []projects.Project{
	{
		Name: "admin",
		ID:   uuid.New().String(),
	},
	{
		Name: "service",
		ID:   uuid.New().String(),
	},
	{
		Name: "project1234",
		ID:   uuid.New().String(),
	},
}

// ResponseHandleToken responds with a valid keystone token and the computeURL in the catalog
func ResponseHandleToken(
	keystoneURL string,
	novaURL string,
	neutronURL string,
) string {
	return fmt.Sprintf(
		`
			{
				"token":{
				   "catalog":[
					  {
						 "endpoints":[
							{
							   "id":"9141a10b3d964db2ac2ce36fec7d32e0",
							   "interface":"internal",
							   "region_id":"RegionOne",
							   "url":"%s",
							   "region":"RegionOne"
							},
							{
							   "id":"e6ec29ecce164c3084ef308478080127",
							   "interface":"public",
							   "region_id":"RegionOne",
							   "url":"%s",
							   "region":"RegionOne"
							}
						 ],
						 "id":"edad7277e52a47b3bfb2b7004f77110f",
						 "type":"identity",
						 "name":"keystone"
					  },
					  {
						 "endpoints":[
							{
							   "id":"3474478de5cf4f4bb6289cadde383522",
							   "interface":"internal",
							   "region_id":"RegionOne",
							   "url":"%s",
							   "region":"RegionOne"
							},
							{
							   "id":"a32b1b4d579a402b8e998f65285ffecc",
							   "interface":"public",
							   "region_id":"RegionOne",
							   "url":"%s",
							   "region":"RegionOne"
							}
						 ],
						 "id":"7d1edf61386547039c4046438f77e8be",
						 "type":"compute",
						 "name":"nova"
					  },
					  {
						 "endpoints":[
							{
							   "id":"3474478de5cf4f4bb6289cadde383522",
							   "interface":"internal",
							   "region_id":"RegionOne",
							   "url":"%s",
							   "region":"RegionOne"
							},
							{
							   "id":"a32b1b4d579a402b8e998f65285ffecc",
							   "interface":"public",
							   "region_id":"RegionOne",
							   "url":"%s",
							   "region":"RegionOne"
							}
						 ],
						 "id":"7d1edf61386547039c4046438f77e8be",
						 "type":"network",
						 "name":"neutron"
					  }
			        ]
				}
			 }
			`, keystoneURL, keystoneURL, novaURL, novaURL, neutronURL, neutronURL)
}

func keystoneHandleProjects(
	f *keystone_helpers.KeystoneAPIFixture,
	w http.ResponseWriter,
	r *http.Request,
) {
	f.LogRequest(r)
	switch r.Method {
	case "GET":
		keystoneGetProject(f, w, r)
	default:
		f.UnexpectedRequest(w, r)
		return
	}
}

// GetProject returns a project by name from the keystoneProjects list
func GetProject(name string) *projects.Project {
	for _, p := range keystoneProjects {
		if p.Name == name {
			return &p
		}
	}
	return nil
}

func keystoneGetProject(
	f *keystone_helpers.KeystoneAPIFixture,
	w http.ResponseWriter,
	r *http.Request,
) {
	nameFilter := r.URL.Query().Get("name")
	var s struct {
		Projects []projects.Project `json:"projects"`
	}
	project := GetProject(nameFilter)
	s.Projects = []projects.Project{*project}

	bytes, err := json.Marshal(&s)
	if err != nil {
		f.InternalError(err, "Error during marshalling response", w, r)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = fmt.Fprint(w, string(bytes))
	f.Log.Info(fmt.Sprintf("GetProject returns %s", string(bytes)))
}

// APIFixtures aggregates all API test fixtures for functional testing
type APIFixtures struct {
	Keystone *keystone_helpers.KeystoneAPIFixture
	Nova     *NovaAPIFixture
	Neutron  *NeutronAPIFixture
}

// SetupAPIFixtures initializes and configures all API fixtures for testing
func SetupAPIFixtures(logger logr.Logger) APIFixtures {
	nova := NewNovaAPIFixtureWithServer(logger)
	nova.Setup()
	DeferCleanup(nova.Cleanup)
	novaURL := nova.Endpoint()

	neutron := NewNeutronAPIFixtureWithServer(logger)
	neutron.Setup()
	DeferCleanup(neutron.Cleanup)
	neutronURL := neutron.Endpoint()

	keystone := keystone_helpers.NewKeystoneAPIFixtureWithServer(logger)
	keystone.Users = map[string]users.User{
		"octavia": {
			Name: "octavia",
			ID:   uuid.New().String(),
		},
	}
	keystone.Setup(
		api.Handler{Pattern: "/", Func: keystone.HandleVersion},
		api.Handler{Pattern: "/v3/users", Func: keystone.HandleUsers},
		api.Handler{Pattern: "/v3/domains", Func: keystone.HandleDomains},
		api.Handler{Pattern: "/v3/projects", Func: func(w http.ResponseWriter, r *http.Request) {
			keystoneHandleProjects(keystone, w, r)
		}},
		api.Handler{Pattern: "/v3/auth/tokens", Func: func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "POST":
				w.Header().Add("Content-Type", "application/json")
				w.WriteHeader(202)
				// ensure keystone returns the simulator endpoints in its catalog
				_, _ = fmt.Fprint(w, ResponseHandleToken(keystone.Endpoint(), novaURL, neutronURL))
			}
		}})
	DeferCleanup(keystone.Cleanup)
	return APIFixtures{
		Keystone: keystone,
		Nova:     nova,
		Neutron:  neutron,
	}
}
