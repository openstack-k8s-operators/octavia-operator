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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/keypairs"
	"github.com/openstack-k8s-operators/lib-common/modules/common/configmap"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	"github.com/openstack-k8s-operators/lib-common/modules/common/secret"
	"github.com/openstack-k8s-operators/lib-common/modules/common/util"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
	"golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NovaKeyPairName stores the name of the nova keypair that holds the public SSH key for access to the amphorae
const NovaKeyPairName string = "octavia-ssh-keypair"

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
	instance *octaviav1.Octavia,
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
	instance *octaviav1.Octavia,
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

func uploadKeypair(
	ctx context.Context,
	instance *octaviav1.Octavia,
	h *helper.Helper,
	pubKey string) error {
	osClient, err := GetOpenstackClient(ctx, instance.Namespace, h)
	if err != nil {
		return fmt.Errorf("error getting openstack client: %w", err)
	}

	computeClient, err := GetComputeClient(osClient)
	if err != nil {
		return fmt.Errorf("error getting compute client: %w", err)
	}

	octaviaUser, err := GetUser(ctx, osClient, instance.Spec.ServiceUser)
	if err != nil {
		return fmt.Errorf("error getting user details from openstack client: %w", err)
	}

	getOpts := keypairs.GetOpts{
		UserID: octaviaUser.ID,
	}
	keypair, _ := keypairs.Get(ctx, computeClient, NovaKeyPairName, getOpts).Extract()

	// keypair exists with a different pubkey, delete keypair
	if keypair != nil && keypair.PublicKey != pubKey {
		deleteOpts := keypairs.DeleteOpts{
			UserID: octaviaUser.ID,
		}
		err := keypairs.Delete(ctx, computeClient, NovaKeyPairName, deleteOpts).ExtractErr()
		if err != nil {
			return fmt.Errorf("error deleting the existing SSH keypair for amphorae: %w", err)
		}
	}

	// keypair doesn't exist or pubkey has changed, update keypair
	if keypair == nil || keypair.PublicKey != pubKey {
		createOpts := keypairs.CreateOpts{
			Name:      NovaKeyPairName,
			Type:      "ssh",
			PublicKey: pubKey,
			UserID:    octaviaUser.ID,
		}
		_, err = keypairs.Create(ctx, computeClient, createOpts).Extract()
		if err != nil {
			return fmt.Errorf("error uploading public key for SSH authentication with amphora: %w", err)
		}
	}
	return nil
}

// EnsureAmpSSHConfig ensures amphora SSH configuration is set up
func EnsureAmpSSHConfig(
	ctx context.Context,
	instance *octaviav1.Octavia,
	h *helper.Helper,
) error {
	cmap, _, err := configmap.GetConfigMap(
		ctx, h, instance, instance.Spec.LoadBalancerSSHPubKey, 10*time.Second)
	if err == nil && cmap.Data != nil {
		// Fail if config map has no data
		if len(cmap.Data) == 0 || cmap.Data["key"] == "" {
			return fmt.Errorf("%w: %s", ErrConfigMapMissingKeyData, instance.Spec.LoadBalancerSSHPubKey)
		}

		err = uploadKeypair(ctx, instance, h, cmap.Data["key"])
		if err != nil {
			return err
		}
	} else {
		if err != nil && !k8serrors.IsNotFound(err) {
			return fmt.Errorf("error retrieving config map %s - %w", instance.Spec.LoadBalancerSSHPubKey, err)
		}

		pubKey, privKey, err := generateECDSAKeys()
		if err != nil {
			return fmt.Errorf("error while generating SSH keys for amphorae: %w", err)
		}

		err = storePrivateKeyAsSecret(ctx, instance, h, privKey)
		if err != nil {
			return fmt.Errorf("error creating ssh key secret %s - %w",
				instance.Spec.LoadBalancerSSHPrivKey, err)
		}

		err = storePublicKeyAsConfigMap(ctx, instance, h, pubKey)
		if err != nil {
			return fmt.Errorf("error creating ssh key config map %s - %w",
				instance.Spec.LoadBalancerSSHPubKey, err)
		}
		err = uploadKeypair(ctx, instance, h, pubKey)
		if err != nil {
			return err
		}
	}
	return nil
}
