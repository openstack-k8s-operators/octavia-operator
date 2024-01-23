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

package amphoracontrollers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/keypairs"
	"github.com/openstack-k8s-operators/lib-common/modules/common/configmap"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	"github.com/openstack-k8s-operators/lib-common/modules/common/secret"
	"github.com/openstack-k8s-operators/lib-common/modules/common/util"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/octavia-operator/pkg/octavia"
	"golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NovaKeyPairName stores the name of the nova keypair that holds the public SSH key for access to the amphorae
const NovaKeyPairName string = "octavia-ssh-keypair"

var (
	onceEnsureSSH   sync.Once
	ensureResultSSH error = nil
)

func generateECDSAKeys() (pubKey string, privKey string, err error) {
	// generate private key
	curve := elliptic.P521()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return "", "", err
	}

	// encode public key
	publicKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		return "", "", err
	}
	pubBytes := ssh.MarshalAuthorizedKey(publicKey)

	// encode private key
	bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}
	privBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: bytes,
	})

	return string(pubBytes), string(privBytes), nil
}

func storePrivateKeyAsSecret(
	ctx context.Context,
	instance *octaviav1.OctaviaAmphoraController,
	h *helper.Helper,
	privKey string,
) error {
	oAmpSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Spec.LoadBalancerSSHPrivKey,
			Namespace: instance.Namespace,
		},
		Data: map[string][]byte{
			"key": []byte(privKey),
		},
	}

	_, _, err := secret.CreateOrPatchSecret(ctx, h, instance, oAmpSecret)
	return err
}

func storePublicKeyAsConfigMap(
	ctx context.Context,
	instance *octaviav1.OctaviaAmphoraController,
	h *helper.Helper,
	pubKey string,
) error {
	cData := map[string]string{"key": pubKey}
	cms := []util.Template{
		{
			Name:         instance.Spec.LoadBalancerSSHPubKey,
			Type:         util.TemplateTypeNone,
			InstanceType: instance.Kind,
			CustomData:   cData,
			Namespace:    instance.Namespace,
		},
	}
	err := configmap.EnsureConfigMaps(ctx, h, instance, cms, nil)
	return err
}

func doEnsureAmpSSHConfig(
	ctx context.Context,
	instance *octaviav1.OctaviaAmphoraController,
	h *helper.Helper,
	log *logr.Logger,
) {
	cmap, _, err := configmap.GetConfigMap(
		ctx, h, instance, instance.Spec.LoadBalancerSSHPubKey, 10*time.Second)
	if err == nil && cmap.Data != nil {
		// Fail if config map has no data
		if len(cmap.Data) == 0 || cmap.Data["key"] == "" {
			ensureResultSSH = fmt.Errorf(
				"ConfigMap %s exists but has no key data",
				instance.Spec.LoadBalancerSSHPubKey)
			return
		}
	} else {
		if err != nil && !k8serrors.IsNotFound(err) {
			ensureResultSSH = fmt.Errorf("Error retrieving config map %s - %w", instance.Spec.LoadBalancerSSHPubKey, err)
			return
		}

		pubKey, privKey, err := generateECDSAKeys()
		if err != nil {
			ensureResultSSH = fmt.Errorf("Error while generating SSH keys for amphorae: %w", err)
			return
		}

		err = storePrivateKeyAsSecret(ctx, instance, h, privKey)
		if err != nil {
			ensureResultSSH = fmt.Errorf("Error creating ssh key secret %s - %w",
				instance.Spec.LoadBalancerSSHPrivKey, err)
			return
		}

		err = storePublicKeyAsConfigMap(ctx, instance, h, pubKey)
		if err != nil {
			ensureResultSSH = fmt.Errorf("Error creating ssh key config map %s - %w",
				instance.Spec.LoadBalancerSSHPubKey, err)
			return
		}

		osClient, err := GetOpenstackClient(ctx, instance, h)
		if err != nil {
			ensureResultSSH = fmt.Errorf("Error getting openstack client: %w", err)
			return
		}

		computeClient, err := octavia.GetComputeClient(osClient)
		if err != nil {
			ensureResultSSH = fmt.Errorf("Error getting compute client: %w", err)
			return
		}

		allPages, err := keypairs.List(computeClient, nil).AllPages()
		if err != nil {
			ensureResultSSH = fmt.Errorf("Could not list keypairs: %w", err)
			return
		}

		allKeyPairs, err := keypairs.ExtractKeyPairs(allPages)
		if err != nil {
			ensureResultSSH = fmt.Errorf("Could not extract keypairs: %w", err)
			return
		}

		var keypairExists bool = false
		for _, kp := range allKeyPairs {
			if kp.Name == NovaKeyPairName {
				keypairExists = true
				break
			}
		}

		if keypairExists {
			err := keypairs.Delete(computeClient, NovaKeyPairName, nil).ExtractErr()
			if err != nil {
				ensureResultSSH = fmt.Errorf("Error deleting the existing SSH keypair for amphorae: %w", err)
				return
			}
		}

		createOpts := keypairs.CreateOpts{
			Name:      NovaKeyPairName,
			Type:      "ssh",
			PublicKey: pubKey,
		}
		_, err = keypairs.Create(computeClient, createOpts).Extract()
		if err != nil {
			ensureResultSSH = fmt.Errorf("Error uploading public key for SSH authentication with amphora: %w", err)
			return
		}
	}
}

// EnsureAmpSSHConfig ensures amphora SSH configuration is set up
func EnsureAmpSSHConfig(
	ctx context.Context,
	instance *octaviav1.OctaviaAmphoraController,
	h *helper.Helper,
	log *logr.Logger,
) error {
	// Do SSH config once, and only once for all services.
	onceEnsureSSH.Do(func() { doEnsureAmpSSHConfig(ctx, instance, h, log) })
	return ensureResultSSH
}
