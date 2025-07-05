// Copyright 2024 PingCAP, Inc. Licensed under Apache-2.0.

package config

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pingcap/log"
	"go.etcd.io/etcd/client/pkg/v3/transport"
	"go.uber.org/zap"

	"github.com/pingcap/tidb-dashboard/pkg/utils/version"
)

const (
	defaultPublicPathPrefix = "/dashboard"

	UIPathPrefix      = "/dashboard/"
	APIPathPrefix     = "/dashboard/api/"
	SwaggerPathPrefix = "/dashboard/api/swagger/"
)

type Config struct {
	DataDir          string
	TempDir          string
	PDEndPoint       string
	PublicPathPrefix string

	ClusterTLSConfig *tls.Config        // TLS config for mTLS authentication between TiDB components.
	ClusterTLSInfo   *transport.TLSInfo // TLS info for mTLS authentication between TiDB components.
	TiDBTLSConfig    *tls.Config        // TLS config for mTLS authentication between TiDB and MySQL client.

	// Certificate monitoring fields
	lastCertFile string
	lastKeyFile  string
	lastCAFile   string
	lastCertHash string
	lastKeyHash  string
	lastCAHash   string

	EnableTelemetry       bool
	EnableExperimental    bool
	EnableKeyVisualizer   bool
	DisableCustomPromAddr bool
	FeatureVersion        string // assign the target TiDB version when running TiDB Dashboard as standalone mode

	NgmTimeout int // in seconds
}

func Default() *Config {
	return &Config{
		DataDir:               "/tmp/dashboard-data",
		TempDir:               "",
		PDEndPoint:            "http://127.0.0.1:2379",
		PublicPathPrefix:      defaultPublicPathPrefix,
		ClusterTLSConfig:      nil,
		ClusterTLSInfo:        nil,
		TiDBTLSConfig:         nil,
		EnableTelemetry:       false,
		EnableExperimental:    false,
		EnableKeyVisualizer:   true,
		DisableCustomPromAddr: false,
		FeatureVersion:        version.PDVersion,
		NgmTimeout:            30, // s
	}
}

func (c *Config) GetClusterHTTPScheme() string {
	if c.ClusterTLSConfig != nil {
		return "https"
	}
	return "http"
}

func (c *Config) NormalizePDEndPoint() error {
	if !strings.HasPrefix(c.PDEndPoint, "http://") && !strings.HasPrefix(c.PDEndPoint, "https://") {
		c.PDEndPoint = "http://" + c.PDEndPoint
	}

	pdEndPoint, err := url.Parse(c.PDEndPoint)
	if err != nil {
		return err
	}

	pdEndPoint.Scheme = c.GetClusterHTTPScheme()
	c.PDEndPoint = pdEndPoint.String()
	return nil
}

func (c *Config) NormalizePublicPathPrefix() {
	if c.PublicPathPrefix == "" {
		c.PublicPathPrefix = defaultPublicPathPrefix
	}
	c.PublicPathPrefix = strings.TrimRight(c.PublicPathPrefix, "/")
}

// MonitorCertificateChanges checks if certificate files have been modified and logs warnings
func (c *Config) MonitorCertificateChanges() {
	if c.ClusterTLSInfo == nil {
		return
	}

	// Calculate current file hashes
	currentCertHash := c.calculateFileHash(c.ClusterTLSInfo.CertFile)
	currentKeyHash := c.calculateFileHash(c.ClusterTLSInfo.KeyFile)
	currentCAHash := c.calculateFileHash(c.ClusterTLSInfo.TrustedCAFile)

	// Check for changes and log warnings
	if c.lastCertFile != "" && c.lastCertHash != "" && currentCertHash != c.lastCertHash {
		log.Warn("Certificate file has been modified",
			zap.String("cert_file", c.ClusterTLSInfo.CertFile),
			zap.String("old_hash", c.lastCertHash),
			zap.String("new_hash", currentCertHash),
		)
	}

	if c.lastKeyFile != "" && c.lastKeyHash != "" && currentKeyHash != c.lastKeyHash {
		log.Warn("Private key file has been modified",
			zap.String("key_file", c.ClusterTLSInfo.KeyFile),
			zap.String("old_hash", c.lastKeyHash),
			zap.String("new_hash", currentKeyHash),
		)
	}

	if c.lastCAFile != "" && c.lastCAHash != "" && currentCAHash != c.lastCAHash {
		log.Warn("CA certificate file has been modified",
			zap.String("ca_file", c.ClusterTLSInfo.TrustedCAFile),
			zap.String("old_hash", c.lastCAHash),
			zap.String("new_hash", currentCAHash),
		)
	}

	// Update stored values
	c.lastCertFile = c.ClusterTLSInfo.CertFile
	c.lastKeyFile = c.ClusterTLSInfo.KeyFile
	c.lastCAFile = c.ClusterTLSInfo.TrustedCAFile
	c.lastCertHash = currentCertHash
	c.lastKeyHash = currentKeyHash
	c.lastCAHash = currentCAHash
}

// calculateFileHash calculates SHA256 hash of a file
func (c *Config) calculateFileHash(filePath string) string {
	if filePath == "" {
		return ""
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Warn("Failed to read file for hash calculation",
			zap.String("file", filePath),
			zap.Error(err),
		)
		return ""
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// StartCertificateMonitoring starts a background goroutine to monitor certificate changes
func (c *Config) StartCertificateMonitoring(ctx context.Context) {
	if c.ClusterTLSInfo == nil {
		return
	}

	// Initialize certificate hashes
	c.MonitorCertificateChanges()

	go func() {
		ticker := time.NewTicker(30 * time.Second) // Check every 30 seconds
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.MonitorCertificateChanges()
			}
		}
	}()
}
