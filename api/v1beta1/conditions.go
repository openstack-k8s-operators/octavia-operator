/*
Copyright 2023.

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

package v1beta1

import (
	condition "github.com/openstack-k8s-operators/lib-common/modules/common/condition"
)

// Octavia Condition Types used by API Objects
const (
	// OctaviaAPIReadyCondition Status=True condition which indicates that the OctaviaAPI is configured and operational.
	OctaviaAPIReadyCondition condition.Type = "OctaviaAPIReady"

	OctaviaHealthManagerReadyCondition condition.Type = "OctaviaHealthManagerReady"

	OctaviaHousekeepingReadyCondition condition.Type = "OctaviaHousekeepingReady"

	OctaviaWorkerReadyCondition condition.Type = "OctaviaWorkerReady"
)

// Common Messages used by API objects
const (
	//
	// OctaviaAPIReady condition messages
	//
	// OctaviaAPIReadyInitMessage
	OctaviaAPIReadyInitMessage = "OctaviaAPI not started"

	// OctaviaAPIReadyErrorMessage
	OctaviaAPIReadyErrorMessage = "OctaviaAPI error occured %s"

	//
	// OctaviaHealthManagerReady condition messages
	//
	// OctaviaHealthManagerReadyInitMessage
	OctaviaHealthManagerReadyInitMessage = "OctaviaHealthManager is not started"

	// OctaviaHealthManagerReadyErrorMessage
	OctaviaHealthManagerReadyErrorMessage = "OctaviaHealthManager error occured %s"

	//
	// OctaviaHousekeepingReady condition messages
	//
	// OctaviaHousekeepingReadyInitMessage
	OctaviaHousekeepingReadyInitMessage = "OctaviaHousekeeping are not started"

	// OctaviaAmphoraControllerReadyErrorMessage
	OctaviaHousekeepingReadyErrorMessage = "OctaviaHousekeeping error occured %s"

	//
	// OctaviaWorkerReady condition messages
	//
	// OctaviaWorkerReadyInitMessage
	OctaviaWorkerReadyInitMessage = "OctaviaWorker are not started"

	// OctaviaAmphoraControllerReadyErrorMessage
	OctaviaWorkerReadyErrorMessage = "OctaviaWorker error occured %s"
)
