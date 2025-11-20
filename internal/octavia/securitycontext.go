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

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
)

const (
	// OctaviaUID is the user ID for running Octavia services
	OctaviaUID int64 = 42437
	// OctaviaGID is the group ID for running Octavia services
	OctaviaGID int64 = 42437
)

// GetOctaviaSecurityContext returns the security context for octavia containers
func GetOctaviaSecurityContext() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		RunAsUser:    ptr.To(OctaviaUID),
		RunAsGroup:   ptr.To(OctaviaGID),
		RunAsNonRoot: ptr.To(true),
	}
}
