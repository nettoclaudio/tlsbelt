// Copyright 2018 tlsbelt authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tlsbelt

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// CertificateValidator is the interface that wraps the basic Validate method.
type CertificateValidator interface {
	Validate(*tls.Certificate) error
}

// BasicCertificateValidator implements a CertificateValidator interface.
type BasicCertificateValidator struct {
	hostname string
	roots    *x509.CertPool
}

// Validate checks if c is ready for use in a production env. When c is not a
// good one, returns a non-nil error describing the problem, otherwise returns
// nil indicating success.
//
// A good certificate should be issued (even though indirectly, when providing
// intermediates) by roots; within the issuing time boundary; and, match the
// Common Name or SAN extension with the server's hostname.
//
// No revocation checking is made on this function.
//
// See x509.Verify to more detailed info about the validation.
func (cv *BasicCertificateValidator) Validate(c *tls.Certificate) error {
	if c == nil || len(c.Certificate) == 0 {
		return errors.New("no certificate provided")
	}

	intermediates := x509.NewCertPool()

	for i := 1; i < len(c.Certificate); i++ {
		intermediate, _ := x509.ParseCertificate(c.Certificate[i])
		intermediates.AddCert(intermediate)
	}

	leafCertificate, _ := x509.ParseCertificate(c.Certificate[0])

	_, err := leafCertificate.Verify(x509.VerifyOptions{
		DNSName:       cv.hostname,
		Roots:         cv.roots,
		Intermediates: intermediates,
	})

	return err
}
