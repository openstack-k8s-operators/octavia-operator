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

	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/keypairs"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/quotasets"

	api "github.com/openstack-k8s-operators/lib-common/modules/test/apis"
)

// NovaAPIFixture provides a test fixture for mocking Nova API responses
type NovaAPIFixture struct {
	api.APIFixture
	QuotaSets       map[string]quotasets.QuotaSet
	DefaultQuotaSet quotasets.QuotaSet
	KeyPairs        map[string]keypairs.KeyPair
}

func (f *NovaAPIFixture) registerHandler(handler api.Handler) {
	f.Server.AddHandler(f.URLBase+handler.Pattern, handler.Func)
}

func (f *NovaAPIFixture) versionHandler(w http.ResponseWriter, r *http.Request) {
	f.LogRequest(r)
	if r.Method != "GET" {
		f.UnexpectedRequest(w, r)
		return
	}

	// Return compute API version information
	response := map[string]interface{}{
		"version": map[string]interface{}{
			"id":     "v2.1",
			"status": "CURRENT",
			"links": []map[string]string{
				{
					"href": f.Server.Endpoint() + f.URLBase,
					"rel":  "self",
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

// Setup initializes the NovaAPIFixture with API handlers and test data
func (f *NovaAPIFixture) Setup() {
	f.registerHandler(api.Handler{Pattern: "/", Func: f.versionHandler})
	f.registerHandler(api.Handler{Pattern: "/os-keypairs", Func: f.keyPairHandler})
	f.registerHandler(api.Handler{Pattern: "/os-keypairs/", Func: f.keyPairHandler})
	f.registerHandler(api.Handler{Pattern: "/os-quota-sets/", Func: f.quotaSetsHandler})
}

func (f *NovaAPIFixture) keyPairHandler(w http.ResponseWriter, r *http.Request) {
	f.LogRequest(r)
	switch r.Method {
	case "GET":
		f.getKeyPair(w, r)
	case "POST":
		f.postKeyPair(w, r)
	case "DELETE":
		f.deleteKeyPair(w, r)
	default:
		f.UnexpectedRequest(w, r)
		return
	}
}

func (f *NovaAPIFixture) getKeyPair(w http.ResponseWriter, r *http.Request) {
	items := strings.Split(r.URL.Path, "/")
	if len(items) == 4 {
		var k struct {
			KeyPair keypairs.KeyPair `json:"keypair"`
		}
		k.KeyPair = keypairs.KeyPair{}
		query := r.URL.Query()
		userID := query["user_id"]
		keyName := items[3]
		for _, keypair := range f.KeyPairs {
			if userID[0] == keypair.UserID && keyName == keypair.Name {
				k.KeyPair = keypair
			}
		}
		bytes, err := json.Marshal(&k)
		if err != nil {
			f.InternalError(err, "Error during marshalling response", w, r)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, string(bytes))
	} else if len(items) == 3 {
		type pair struct {
			KeyPair keypairs.KeyPair `json:"keypair"`
		}
		var k struct {
			KeyPairs []pair `json:"keypairs"`
		}
		k.KeyPairs = []pair{}
		query := r.URL.Query()
		userID := query["user_id"]
		for _, keypair := range f.KeyPairs {
			if len(userID) > 0 && userID[0] != keypair.UserID {
				continue
			}
			k.KeyPairs = append(k.KeyPairs, pair{KeyPair: keypair})
		}
		bytes, err := json.Marshal(&k)
		if err != nil {
			f.InternalError(err, "Error during marshalling response", w, r)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, string(bytes))
	}
}

func (f *NovaAPIFixture) postKeyPair(w http.ResponseWriter, r *http.Request) {
	bytes, err := io.ReadAll(r.Body)
	if err != nil {
		f.InternalError(err, "Error reading request body", w, r)
		return
	}

	var k struct {
		KeyPair keypairs.KeyPair `json:"keypair"`
	}

	err = json.Unmarshal(bytes, &k)
	if err != nil {
		f.InternalError(err, "Error during marshalling response", w, r)
		return
	}

	f.KeyPairs[k.KeyPair.Name] = k.KeyPair

	bytes, err = json.Marshal(&k)
	if err != nil {
		f.InternalError(err, "Error during marshalling response", w, r)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(201)
	_, _ = fmt.Fprint(w, string(bytes))
}

func (f *NovaAPIFixture) deleteKeyPair(w http.ResponseWriter, r *http.Request) {
	items := strings.Split(r.URL.Path, "/")
	keypair := items[len(items)-1]

	delete(f.KeyPairs, keypair)

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(202)
}

func (f *NovaAPIFixture) quotaSetsHandler(w http.ResponseWriter, r *http.Request) {
	f.LogRequest(r)
	switch r.Method {
	case "GET":
		f.getQuotaSets(w, r)
	case "PUT":
		f.putQuotaSets(w, r)
	default:
		f.UnexpectedRequest(w, r)
		return
	}
}

func (f *NovaAPIFixture) getQuotaSets(w http.ResponseWriter, r *http.Request) {
	items := strings.Split(r.URL.Path, "/")
	tenantID := items[len(items)-1]

	var q struct {
		Quotaset quotasets.QuotaSet `json:"quota_set"`
	}
	if quotaset, ok := f.QuotaSets[tenantID]; ok {
		q.Quotaset = quotaset
	} else {
		q.Quotaset = f.DefaultQuotaSet
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

func (f *NovaAPIFixture) putQuotaSets(w http.ResponseWriter, r *http.Request) {
	items := strings.Split(r.URL.Path, "/")
	tenantID := items[len(items)-1]

	bytes, err := io.ReadAll(r.Body)
	if err != nil {
		f.InternalError(err, "Error reading request body", w, r)
		return
	}
	var q struct {
		Quotaset quotasets.QuotaSet `json:"quota_set"`
	}
	err = json.Unmarshal(bytes, &q)
	if err != nil {
		f.InternalError(err, "Error during unmarshalling request", w, r)
		return
	}
	f.QuotaSets[tenantID] = q.Quotaset

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = fmt.Fprint(w, string(bytes))
}

// NewNovaAPIFixtureWithServer creates a new NovaAPIFixture with its own test server
func NewNovaAPIFixtureWithServer(log logr.Logger) *NovaAPIFixture {
	server := &api.FakeAPIServer{}
	server.Setup(log)
	fixture := AddNovaAPIFixture(log, server)
	fixture.OwnsServer = true
	return fixture
}

// AddNovaAPIFixture adds a NovaAPIFixture to an existing test server
func AddNovaAPIFixture(log logr.Logger, server *api.FakeAPIServer) *NovaAPIFixture {
	fixture := &NovaAPIFixture{
		APIFixture: api.APIFixture{
			Server:     server,
			Log:        log,
			URLBase:    "/compute",
			OwnsServer: false,
		},
		DefaultQuotaSet: quotasets.QuotaSet{
			RAM:                100,
			Cores:              100,
			Instances:          50,
			ServerGroups:       10,
			ServerGroupMembers: 10,
		},
		QuotaSets: map[string]quotasets.QuotaSet{},
		KeyPairs:  map[string]keypairs.KeyPair{},
	}
	return fixture
}
