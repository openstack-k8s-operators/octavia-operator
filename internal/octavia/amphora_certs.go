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
	"unicode"

	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	"github.com/openstack-k8s-operators/lib-common/modules/common/secret"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	subjectDefault = pkix.Name{
		CommonName:         "www.example.com",
		Organization:       []string{"OpenStack"},
		OrganizationalUnit: []string{"Octavia Amphorae"},
		Country:            []string{"DE"},
		Province:           []string{"Bavaria"},
		Locality:           []string{"Piding"},
	}
)

const (
	// OctaviaCertSecretVersion defines the version of the certificate secret format
	OctaviaCertSecretVersion int = 2
)

// generateKey generates a PEM encoded private RSA key and applies PEM
// encryption if given passphrase is not an empty string.
func generateKey(passphrase []byte) (*rsa.PrivateKey, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		err = fmt.Errorf("error private key to PKCS #8 form: %w", err)
		return priv, nil, err
	}

	var pemBlock *pem.Block
	if passphrase != nil {
		pemBlock, err = EncryptPrivateKey(pkcs8Key, passphrase)
		if err != nil {
			err = fmt.Errorf("error encrypting private key: %w", err)
			return priv, nil, err
		}
	} else {
		pemBlock = &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Key}
	}

	privPEM := new(bytes.Buffer)
	err = pem.Encode(privPEM, pemBlock)
	if err != nil {
		return priv, nil, err
	}

	return priv, privPEM.Bytes(), nil
}

func generateCACert(caPrivKey *rsa.PrivateKey, commonName string) ([]byte, *x509.Certificate, error) {
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               subjectDefault,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10 /* years */, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
	}
	caTemplate.Subject.CommonName = commonName

	caBytes, err := x509.CreateCertificate(
		rand.Reader, caTemplate, caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}
	caCertPEM := new(bytes.Buffer)
	err = pem.Encode(caCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return nil, nil, err
	}
	return caCertPEM.Bytes(), caTemplate, nil
}

// Create a certificate and key for the client and sign it with the CA
func generateClientCert(caTemplate *x509.Certificate, certPrivKey *rsa.PrivateKey, caPrivKey *rsa.PrivateKey, commonName string) ([]byte, error) {

	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               subjectDefault,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10 /* years */, 0, 0),
		IsCA:                  false,
		BasicConstraintsValid: false,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection},
	}
	certTemplate.Subject.CommonName = commonName

	certBytes, err := x509.CreateCertificate(
		rand.Reader, certTemplate, caTemplate, &certPrivKey.PublicKey, caPrivKey)
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

func validatePassphrase(passphrase []byte) error {
	for _, c := range string(passphrase) {
		if !unicode.IsPrint(c) {
			return ErrCAPassphraseInvalidChars
		}
	}
	return nil
}

// EnsureAmphoraCerts ensures Amphora certificates exist in the secret store
func EnsureAmphoraCerts(
	ctx context.Context,
	instance *octaviav1.Octavia,
	h *helper.Helper) error {
	var oAmpSecret *corev1.Secret
	var serverCAPass []byte

	certsSecretName := fmt.Sprintf("%s-certs-secret", instance.Name)
	_, _, err := secret.GetSecret(ctx, h, certsSecretName, instance.Namespace)
	if err != nil {
		if !k8serrors.IsNotFound(err) {
			return fmt.Errorf("error retrieving secret %s - %w", certsSecretName, err)
		}

		serverCAPassSecretName := fmt.Sprintf("%s-ca-passphrase", instance.Name)
		cAPassSecret, _, err := secret.GetSecret(
			ctx, h, serverCAPassSecretName, instance.Namespace)
		if err != nil {
			return fmt.Errorf("error retrieving secret %s needed to encrypt the generated key - %w", serverCAPassSecretName, err)
		}
		serverCAPass = cAPassSecret.Data["server-ca-passphrase"]

		if err = validatePassphrase(serverCAPass); err != nil {
			return err
		}

		serverCAKey, serverCAKeyPEM, err := generateKey(serverCAPass)
		if err != nil {
			return fmt.Errorf("error while generating server CA key: %w", err)
		}
		serverCACert, _, err := generateCACert(serverCAKey, "Octavia server CA")
		if err != nil {
			return fmt.Errorf("error while generating server CA certificate: %w", err)
		}

		clientCAKey, clientCAKeyPEM, err := generateKey(nil)
		if err != nil {
			return fmt.Errorf("error while generating client CA key: %w", err)
		}
		clientCACert, clientCATemplate, err := generateCACert(clientCAKey, "Octavia client CA")
		if err != nil {
			return fmt.Errorf("error while generating amphora client CA certificate: %w", err)
		}

		clientKey, clientKeyPEM, err := generateKey(nil)
		if err != nil {
			return fmt.Errorf("error while generating amphora client key: %w", err)
		}
		clientCert, err := generateClientCert(clientCATemplate, clientKey, clientCAKey, "Octavia controller")
		if err != nil {
			return fmt.Errorf("error while generating amphora client certificate: %w", err)
		}
		clientKeyAndCert := append(clientKeyPEM, clientCert...)

		oAmpSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      certsSecretName,
				Namespace: instance.Namespace,
			},

			// note: the client CA key seem to be needed only for generating the
			// client CA cert and should not get mounted to the pods
			Data: map[string][]byte{
				"server_ca.key.pem":  serverCAKeyPEM,
				"server_ca.cert.pem": serverCACert,
				"client_ca.key.pem":  clientCAKeyPEM,
				"client_ca.cert.pem": clientCACert,
				// Unencrypted client key and cert
				"client.cert-and-key.pem": clientKeyAndCert,
				"version":                 fmt.Appendf(nil, "%d", OctaviaCertSecretVersion),
			},
		}

		_, _, err = secret.CreateOrPatchSecret(ctx, h, instance, oAmpSecret)
		if err != nil {
			return fmt.Errorf("error creating certs secret %s - %w",
				certsSecretName, err)
		}
	}
	return nil
}
