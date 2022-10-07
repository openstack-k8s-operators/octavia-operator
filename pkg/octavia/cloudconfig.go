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

// OpenStackConfig type
type OpenStackConfig struct {
	Clouds struct {
		Default struct {
			Auth struct {
				AuthURL           string `yaml:"auth_url"`
				ProjectName       string `yaml:"project_name"`
				UserName          string `yaml:"username"`
				UserDomainName    string `yaml:"user_domain_name"`
				ProjectDomainName string `yaml:"project_domain_name"`
			} `yaml:"auth"`
			RegionName string `yaml:"region_name"`
		} `yaml:"default"`
	}
}

// OpenStackConfigSecret type
type OpenStackConfigSecret struct {
	Clouds struct {
		Default struct {
			Auth struct {
				Password string `yaml:"password"`
			}
		}
	}
}
