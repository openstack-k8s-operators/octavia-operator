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

// Package octavia provides core functionality for managing Octavia load balancer components
package octavia

import "errors"

// Common static errors for octavia components
var (
	ErrNetworkAttachmentsEmpty             = errors.New("networkAttachments list is empty")
	ErrNetworkAttachmentConfig             = errors.New("not all pods have interfaces with ips as configured in NetworkAttachments")
	ErrOpenstackServerCAPassphraseNotFound = errors.New("OpenStack server CA passphrase secret not found")
	ErrOctaviaFlavorsConfig                = errors.New("none of the Octavia flavors could be configured")
	ErrCAPassphraseInvalidChars            = errors.New("error: CA Passphrase contains invalid characters")
	ErrConfigMapMissingKeyData             = errors.New("ConfigMap exists but has no key data")

	// Client-related errors
	ErrServiceClientConfigNilInstance = errors.New("cannot get service client config with nil instance")
	ErrInvalidClientType              = errors.New("invalid client type")
	ErrCABundleSecretNotFound         = errors.New("the CABundleSecret not found")
	ErrCannotFindDomain               = errors.New("cannot find domain")
	ErrCannotFindProjectInDomain      = errors.New("cannot find project in domain")
	ErrCannotFindProject              = errors.New("cannot find project")
	ErrCannotFindUser                 = errors.New("cannot find user")
	ErrGettingClientForUserRoles      = errors.New("error while getting a client for setting user roles")
	ErrGettingProjectInDomain         = errors.New("error while getting project in domain")
	ErrGettingDomain                  = errors.New("error while getting domain")
	ErrGettingUserInDomain            = errors.New("error while getting user in domain")
	ErrSettingUserRole                = errors.New("error when setting role to user in project")

	// Network-related errors
	ErrCannotFindNetwork           = errors.New("cannot find network")
	ErrRouterNotUp                 = errors.New("router is not up")
	ErrPredictableIPAllocation     = errors.New("predictable IPs: cannot allocate IP addresses")
	ErrPredictableIPOutOfAddresses = errors.New("predictable IPs: out of available addresses")
	ErrCannotAllocateIPAddresses   = errors.New("cannot allocate IP addresses")
	ErrCannotFindGatewayInfo       = errors.New("cannot find gateway information in network attachment")
)
