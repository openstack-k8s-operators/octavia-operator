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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/go-logr/logr"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	"github.com/openstack-k8s-operators/lib-common/modules/common/secret"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

var (
	subjectDefault = pkix.Name{
		Organization:  []string{"Dis"},
		Country:       []string{"US"},
		Province:      []string{"Oregon"},
		Locality:      []string{"Springfield"},
		StreetAddress: []string{"Denial"},
		PostalCode:    []string{""},
		CommonName:    "www.example.com",
	}
)

// generateKey generates a PEM encoded private RSA key and applies PEM
// encryption if given passphrase is not an empty string.
func generateKey(passphrase []byte) (*rsa.PrivateKey, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	var pemBlock *pem.Block
	if passphrase != nil {
		pemBlock, err = x509.EncryptPEMBlock( //nolint:staticcheck
			rand.Reader,
			"RSA PRIVATE KEY",
			x509.MarshalPKCS1PrivateKey(priv),
			passphrase,
			x509.PEMCipherAES128)
		if err != nil {
			fmt.Println("Error encrypting private CA key:", err)
			return priv, nil, err
		}
	} else {
		privBytes := x509.MarshalPKCS1PrivateKey(priv)
		pemBlock = &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}
	}

	privPEM := new(bytes.Buffer)
	err = pem.Encode(privPEM, pemBlock)
	if err != nil {
		return priv, nil, err
	}

	return priv, privPEM.Bytes(), nil
}

func generateCACert(caPrivKey *rsa.PrivateKey, commonName string) ([]byte, error) {
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               subjectDefault,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
	}
	caTemplate.Subject.CommonName = commonName

	caBytes, err := x509.CreateCertificate(
		rand.Reader, caTemplate, caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}
	caCertPEM := new(bytes.Buffer)
	err = pem.Encode(caCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return nil, err
	}
	return caCertPEM.Bytes(), nil
}

// Create a certificate and key for the client and sign it with the CA
func generateClientCert(caCertPEM []byte, caPrivKey *rsa.PrivateKey) ([]byte, error) {

	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               subjectDefault,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 1, 0),
		IsCA:                  false,
		BasicConstraintsValid: false,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection},
	}

	certBytes, err := x509.CreateCertificate(
		rand.Reader, certTemplate, certTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}

	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, err
	}

	return certPEM.Bytes(), nil
}

// EnsureAmphoraCerts ensures Amphora certificates exist in the secret store
func EnsureAmphoraCerts(ctx context.Context, instance *octaviav1.OctaviaAmphoraController, h *helper.Helper, log *logr.Logger) error {
	var oAmpSecret *corev1.Secret
	var serverCAPass []byte = nil

	_, _, err := secret.GetSecret(ctx, h, instance.Spec.LoadBalancerCerts, instance.Namespace)
	if err != nil {
		if !k8serrors.IsNotFound(err) {
			err = fmt.Errorf("Error retrieving secret %s - %w", instance.Spec.LoadBalancerCerts, err)
			return err
		}

		cAPassSecret, _, err := secret.GetSecret(
			ctx, h, instance.Spec.CAKeyPassphraseSecret, instance.Namespace)
		if err != nil {
			log.Info("Could not read server CA passphrase. No encryption will be applied to the generated key.")
		} else {
			serverCAPass = cAPassSecret.Data["server-ca-passphrase"]
		}

		serverCAKey, serverCAKeyPEM, err := generateKey(serverCAPass)
		if err != nil {
			err = fmt.Errorf("Error while generating server CA key: %w", err)
			return err
		}
		serverCACert, err := generateCACert(serverCAKey, "Octavia server CA")
		if err != nil {
			err = fmt.Errorf("Error while generating server CA certificate: %w", err)
			return err
		}

		clientCAKey, _, err := generateKey(nil)
		if err != nil {
			err = fmt.Errorf("Error while generating client CA key: %w", err)
			return err
		}
		clientCACert, err := generateCACert(clientCAKey, "Octavia client CA")
		if err != nil {
			err = fmt.Errorf("Error while generating amphora client CA certificate: %w", err)
			return err
		}

		clientKey, clientKeyPEM, err := generateKey(nil)
		if err != nil {
			err = fmt.Errorf("Error while generating amphora client key: %w", err)
			return err
		}
		clientCert, err := generateClientCert(clientCACert, clientKey)
		if err != nil {
			err = fmt.Errorf("Error while generating amphora client certificate: %w", err)
			return err
		}
		clientKeyAndCert := append(clientKeyPEM, clientCert...)

		oAmpSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      instance.Spec.LoadBalancerCerts,
				Namespace: instance.Namespace,
			},

			// note: the client CA key seem to be needed only for generating the
			// client CA cert and should not get mounted to the pods
			Data: map[string][]byte{
				"server_ca.key.pem":  serverCAKeyPEM,
				"server_ca.cert.pem": serverCACert,
				"client_ca.cert.pem": clientCACert,
				// Unencrypted client key and cert
				"client.cert-and-key.pem": clientKeyAndCert,
			},
		}

		// err = h.GetClient().Create(ctx, oAmpSecret)
		_, result, err := secret.CreateOrPatchSecret(ctx, h, instance, oAmpSecret)

		if err != nil {
			err = fmt.Errorf("Error creating certs secret %s - %w",
				instance.Spec.LoadBalancerCerts, err)
			return err
		} else if result != controllerutil.OperationResultNone {
			return nil
		}
	}

	return nil
}
