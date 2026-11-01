package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"transfer/internal/wire"
)

const certLife = 10 * 365 * 24 * time.Hour

// loadOrMakeCert keeps one long-lived self-signed certificate in the state
// directory. There is no CA in this design: the client pins the certificate
// fingerprint, which reaches it through the token txt and is then cached
// trust-on-first-use so a later swap gets caught.
func (h *hub) loadOrMakeCert() error {
	certPath := filepath.Join(h.cfg.State, "relay-cert.pem")
	keyPath := filepath.Join(h.cfg.State, "relay-key.pem")

	if certPEM, err := os.ReadFile(certPath); err == nil {
		keyPEM, kerr := os.ReadFile(keyPath)
		if kerr != nil {
			return fmt.Errorf("%s exists but %s is missing: %w", certPath, keyPath, kerr)
		}
		c, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return fmt.Errorf("stored key pair does not load: %w", err)
		}
		if len(c.Certificate) == 0 {
			return fmt.Errorf("stored certificate is empty")
		}
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			return fmt.Errorf("stored certificate does not parse: %w", err)
		}
		if time.Until(leaf.NotAfter) > 30*24*time.Hour {
			h.cert = &c
			h.pin = wire.PinOf(c.Certificate[0])
			return nil
		}
		h.log.Printf("certificate at %s expires %s, replacing", certPath, leaf.NotAfter.Format(time.RFC3339))
	}

	c, der, leaf, err := h.newSelfSigned()
	if err != nil {
		return err
	}
	if err := writePEM(certPath, "CERTIFICATE", der); err != nil {
		return err
	}
	signKey, ok := c.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("generated key is the wrong type")
	}
	kb, err := x509.MarshalPKCS8PrivateKey(signKey)
	if err != nil {
		return err
	}
	if err := writePEM(keyPath, "PRIVATE KEY", kb); err != nil {
		return err
	}

	h.cert = c
	h.pin = wire.PinOf(der)
	h.log.Printf("new certificate, valid until %s, pin %s", leaf.NotAfter.Format(time.RFC3339), h.pin)
	return nil
}

func (h *hub) newSelfSigned() (*tls.Certificate, []byte, *x509.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, err
	}

	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "supertransfer-relay", Organization: []string{"SuperTransfer"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(certLife),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost", "supertransfer-relay"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// Everything the clients are told to dial goes in the SAN list, so the pin
	// check stays the only trust decision and a later address change is safe.
	if host, _, err := net.SplitHostPort(h.cfg.Advertise); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if host != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, host)
		}
	}
	for _, ip := range localIPv4s() {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, pub, priv)
	if err != nil {
		return nil, nil, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, der, leaf, nil
}

func writePEM(path, typ string, b []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: b})
}
