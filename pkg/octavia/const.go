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
	// ServiceType -
	ServiceType = "load-balancer"

	// DatabaseName - Name of the database used in CREATE DATABASE statement
	// for the main octavia database
	DatabaseName = "octavia"

	// PersistenceDatabaseName - Name of the database used in CREATE DATABASE statement
	// for the persistence database
	PersistenceDatabaseName = "octavia_persistence"

	// DatabaseCRName - Name of the MariaDBDatabase CR
	DatabaseCRName = "octavia"

	// PersistenceDatabaseCRName - Name of the MariaDBDatabase CR
	PersistenceDatabaseCRName = "octavia-persistence"

	// DatabaseUsernamePrefix - used by EnsureMariaDBAccount when a new username
	// is to be generated, e.g. "octavia_e5a4", "octavia_78bc", etc
	DatabaseUsernamePrefix = "octavia"

	// OctaviaPublicPort -
	OctaviaPublicPort int32 = 9876
	// OctaviaInternalPort -
	OctaviaInternalPort int32 = 9876

	// ApacheInternalPort -
	ApacheInternalPort int32 = 80

	// AdminTenant is the default admin tenant name for OpenStack
	AdminTenant = "admin"

	// HmConfigMap ...
	HmConfigMap = "octavia-hmport-map"
)
