/*

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

package octavia

const (
	// ServiceName -
	ServiceName = "octavia"
	// ServiceAccount -
	ServiceAccount = "octavia-operator-octavia"
	// DatabaseName -
	DatabaseName = "octavia"

	// OctaviaAdminPort -
	OctaviaAdminPort int32 = 9876
	// OctaviaPublicPort -
	OctaviaPublicPort int32 = 9876
	// OctaviaInternalPort -
	OctaviaInternalPort int32 = 9876

	// KollaDbSyncConfig -
	KollaDbSyncConfig = "/var/lib/config-data/merged/octavia-api-db-sync.json"
	// KollaConfig -
	KollaConfig = "/var/lib/config-data/merged/octavia-api-config.json"
)
