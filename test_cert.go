package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
)

func main() {
	// Load CA certificate
	caCert, err := ioutil.ReadFile("/tidb-deploy-test-tls/pd-2179/tls/ca.crt")
	if err != nil {
		log.Fatal("Failed to read CA cert", err)
	}

	// Load client certificate
	cert, err := ioutil.ReadFile("/tidb-deploy-test-tls/pd-2179/tls/pd.crt")
	if err != nil {
		log.Fatal("Failed to read client cert", err)
	}

	// Load client key
	key, err := ioutil.ReadFile("/tidb-deploy-test-tls/pd-2179/tls/pd.pem")
	if err != nil {
		log.Fatal("Failed to read client key", err)
	}

	// Parse client certificate and key
	tlsCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		log.Fatal("Failed to parse client certificate", err)
	}

	// Create certificate pool for CA
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatal("Failed to append CA cert")
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      caCertPool,
	}

	fmt.Printf("Manual TLS Configuration:\n")
	fmt.Printf("  Cert count: %d\n", len(tlsConfig.Certificates))
	fmt.Printf("  Has root CAs: %v\n", tlsConfig.RootCAs != nil)
	fmt.Printf("  Insecure skip verify: %v\n", tlsConfig.InsecureSkipVerify)

	if len(tlsConfig.Certificates) > 0 {
		fmt.Printf("  Certificate subject: %s\n", tlsConfig.Certificates[0].Leaf.Subject)
	}
}
