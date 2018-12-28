package tlsbelt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBasicCertificateValidator_Validate(t *testing.T) {
	t.Run("When the certificate provided is null, should return an error", func(t *testing.T) {
		validator := &BasicCertificateValidator{
			hostname: "tsuru.example.org",
		}

		assert.NotNil(t, validator.Validate(nil))
	})

	t.Run("When certificate is not parsed in DER, should return an error", func(t *testing.T) {
		validator := &BasicCertificateValidator{
			hostname: "tsuru.example.org",
		}

		assert.NotNil(t, validator.Validate(&tls.Certificate{}))
	})

	t.Run("When hostname field is empty, should ignore should return no error", func(t *testing.T) {
		certificate, err := generateCertificate(&x509.Certificate{
			SerialNumber: big.NewInt(1000),
			Subject: pkix.Name{
				Organization: []string{"tsuru.io"},
				CommonName:   "Tsuru CA #1",
			},
			SubjectKeyId:          []byte{1, 2, 3, 4, 5},
			NotAfter:              time.Now().Add(time.Minute),
			NotBefore:             time.Now(),
			DNSNames:              []string{"tsuru.example.org"},
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}, nil)

		assert.Nil(t, err)

		x509Certificate, err := x509.ParseCertificate(certificate.Certificate[0])
		assert.Nil(t, err)

		roots := x509.NewCertPool()
		roots.AddCert(x509Certificate)

		validator := &BasicCertificateValidator{
			hostname: "",
			roots:    roots,
		}

		assert.Nil(t, validator.Validate(certificate))
	})

	t.Run("When a valid trusted self-signed certificate is provided, should return no error", func(t *testing.T) {
		certificate, err := generateCertificate(&x509.Certificate{
			SerialNumber: big.NewInt(1000),
			Subject: pkix.Name{
				Organization: []string{"tsuru.io"},
				CommonName:   "Tsuru CA #1",
			},
			SubjectKeyId:          []byte{1, 2, 3, 4, 5},
			NotAfter:              time.Now().Add(time.Minute),
			NotBefore:             time.Now(),
			DNSNames:              []string{"tsuru.example.org"},
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}, nil)

		assert.Nil(t, err)

		x509Certificate, err := x509.ParseCertificate(certificate.Certificate[0])
		assert.Nil(t, err)

		roots := x509.NewCertPool()
		roots.AddCert(x509Certificate)

		cv := &BasicCertificateValidator{
			hostname: "tsuru.example.org",
			roots:    roots,
		}

		assert.Nil(t, cv.Validate(certificate))
	})

	t.Run("When certificate has been expired, should return an error", func(t *testing.T) {
		certificate, err := generateCertificate(&x509.Certificate{
			SerialNumber: big.NewInt(1000),
			Subject: pkix.Name{
				Organization: []string{"tsuru.io"},
				CommonName:   "Tsuru CA #1",
			},
			SubjectKeyId:          []byte{1, 2, 3, 4, 5},
			NotAfter:              time.Now().Add(time.Second * -30),
			NotBefore:             time.Now().Add(time.Minute * -1),
			DNSNames:              []string{"tsuru.example.org"},
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}, nil)

		assert.Nil(t, err)

		x509Certificate, err := x509.ParseCertificate(certificate.Certificate[0])
		assert.Nil(t, err)

		roots := x509.NewCertPool()
		roots.AddCert(x509Certificate)

		cv := &BasicCertificateValidator{
			hostname: "tsuru.example.org",
			roots:    roots,
		}

		assert.NotNil(t, cv.Validate(certificate))
	})

	t.Run("When certificate is not valid yet, should return an error", func(t *testing.T) {
		certificate, err := generateCertificate(&x509.Certificate{
			SerialNumber: big.NewInt(1000),
			Subject: pkix.Name{
				Organization: []string{"tsuru.io"},
				CommonName:   "Tsuru CA #1",
			},
			SubjectKeyId:          []byte{1, 2, 3, 4, 5},
			NotAfter:              time.Now().Add(time.Minute * 2),
			NotBefore:             time.Now().Add(time.Minute),
			DNSNames:              []string{"tsuru.example.org"},
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}, nil)

		assert.Nil(t, err)

		x509Certificate, err := x509.ParseCertificate(certificate.Certificate[0])
		assert.Nil(t, err)

		roots := x509.NewCertPool()
		roots.AddCert(x509Certificate)

		cv := &BasicCertificateValidator{
			hostname: "tsuru.example.org",
			roots:    roots,
		}

		assert.NotNil(t, cv.Validate(certificate))
	})

	t.Run("When certificate name mismatch with hostname provided, should return an error", func(t *testing.T) {
		certificate, err := generateCertificate(&x509.Certificate{
			SerialNumber: big.NewInt(1000),
			Subject: pkix.Name{
				Organization: []string{"tsuru.io"},
				CommonName:   "Tsuru CA #1",
			},
			SubjectKeyId:          []byte{1, 2, 3, 4, 5},
			NotAfter:              time.Now().Add(time.Minute * 2),
			NotBefore:             time.Now().Add(time.Minute),
			DNSNames:              []string{"tsuru.example.org"},
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}, nil)

		assert.Nil(t, err)

		x509Certificate, err := x509.ParseCertificate(certificate.Certificate[0])
		assert.Nil(t, err)

		roots := x509.NewCertPool()
		roots.AddCert(x509Certificate)

		cv := &BasicCertificateValidator{
			hostname: "wrongdomain.tsuru.example.org",
			roots:    roots,
		}

		assert.NotNil(t, cv.Validate(certificate))
	})

	t.Run("When the certificate was signed by an trusted intermediate certificate, should return no error", func(t *testing.T) {
		rootCertificate, err := generateCertificate(&x509.Certificate{
			SerialNumber: big.NewInt(1000),
			Subject: pkix.Name{
				Organization: []string{"tsuru.io"},
				CommonName:   "Tsuru CA #1",
			},
			SubjectKeyId:          []byte{1, 2, 3, 4, 5},
			NotAfter:              time.Now().Add(time.Minute * 10),
			NotBefore:             time.Now().Add(time.Minute * -10),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}, nil)

		assert.Nil(t, err)

		intermediateCertificate, err := generateCertificate(&x509.Certificate{
			SerialNumber: big.NewInt(1010),
			Subject: pkix.Name{
				CommonName:   "Tsuru Intermediate Authority",
				Organization: []string{"Tsuru"},
			},
			SubjectKeyId:          []byte{1, 2, 3, 4, 6},
			NotAfter:              time.Now().Add(time.Minute * 5),
			NotBefore:             time.Now(),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}, rootCertificate)

		assert.Nil(t, err)

		leafCertificate, err := generateCertificate(&x509.Certificate{
			SerialNumber: big.NewInt(2000),
			Subject: pkix.Name{
				Organization: []string{"Tsuru"},
			},
			SubjectKeyId:          []byte{1, 2, 3, 4, 7},
			NotAfter:              time.Now().Add(time.Minute),
			NotBefore:             time.Now(),
			DNSNames:              []string{"tsuru.example.org"},
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}, intermediateCertificate)

		assert.Nil(t, err)

		x509RootCertificate, err := x509.ParseCertificate(rootCertificate.Certificate[0])
		assert.Nil(t, err)

		roots := x509.NewCertPool()
		roots.AddCert(x509RootCertificate)

		validator := &BasicCertificateValidator{
			hostname: "tsuru.example.org",
			roots:    roots,
		}

		leafCertificate.Certificate = append(leafCertificate.Certificate, intermediateCertificate.Certificate[0])

		assert.Nil(t, validator.Validate(leafCertificate))
	})
}

func generateCertificate(template *x509.Certificate, parent *tls.Certificate) (*tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)

	if err != nil {
		return nil, err
	}

	var certificateBytes []byte

	if parent == nil {
		certificateBytes, err = x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	} else {
		parentX509, err := x509.ParseCertificate(parent.Certificate[0])
		if err != nil {
			return nil, err
		}
		certificateBytes, err = x509.CreateCertificate(rand.Reader, template, parentX509, privateKey.Public(), parent.PrivateKey)
	}

	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)

	return &certificate, err
}
