// Copyright 2024 PingCAP, Inc. Licensed under Apache-2.0.

package pd

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/pingcap/log"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/pingcap/tidb-dashboard/pkg/config"
	"github.com/pingcap/tidb-dashboard/pkg/httpc"
	"github.com/pingcap/tidb-dashboard/util/distro"
)

var ErrPDClientRequestFailed = ErrNS.NewType("client_request_failed")

const (
	defaultPDTimeout = time.Second * 10
)

type Client struct {
	httpScheme    string
	baseURL       string
	withoutPrefix bool
	httpClient    *httpc.Client
	lifecycleCtx  context.Context
	timeout       time.Duration
}

func NewPDClient(lc fx.Lifecycle, httpClient *httpc.Client, config *config.Config) *Client {
	client := &Client{
		httpClient:   httpClient,
		httpScheme:   config.GetClusterHTTPScheme(),
		baseURL:      config.PDEndPoint,
		lifecycleCtx: nil,
		timeout:      defaultPDTimeout,
	}

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			client.lifecycleCtx = ctx
			return nil
		},
	})

	return client
}

func (c Client) WithBaseURL(baseURL string) *Client {
	c.baseURL = baseURL
	return &c
}

func (c Client) WithAddress(host string, port int) *Client {
	c.baseURL = fmt.Sprintf("%s://%s", c.httpScheme, net.JoinHostPort(host, strconv.Itoa(port)))
	return &c
}

func (c Client) WithTimeout(timeout time.Duration) *Client {
	c.timeout = timeout
	return &c
}

func (c Client) WithoutPrefix() *Client {
	c.withoutPrefix = true
	return &c
}

func (c Client) getPrefix() string {
	if c.withoutPrefix {
		return ""
	}
	return "/pd/api/v1"
}

func (c Client) AddRequestHeader(key, value string) *Client {
	c.httpClient = c.httpClient.CloneAndAddRequestHeader(key, value)
	return &c
}

func (c *Client) Get(relativeURI string) (*httpc.Response, error) {
	uri := fmt.Sprintf("%s%s%s", c.baseURL, c.getPrefix(), relativeURI)
	return c.httpClient.WithTimeout(c.timeout).Send(c.lifecycleCtx, uri, http.MethodGet, nil, ErrPDClientRequestFailed, distro.R().PD)
}

func (c *Client) SendGetRequest(relativeURI string) ([]byte, error) {
	// Monitor certificate changes before PD request
	if c.httpClient.Config != nil {
		c.httpClient.Config.MonitorCertificateChanges()
	}

	res, err := c.Get(relativeURI)
	if err != nil {
		// Print certificate information when PD request fails
		log.Error("PD request failed, printing certificate info for debugging",
			zap.String("uri", relativeURI),
			zap.String("base_url", c.baseURL),
			zap.String("http_scheme", c.httpScheme),
			zap.Error(err),
		)

		// Try to get TLS config info from http client
		if transport, ok := c.httpClient.Transport.(*http.Transport); ok && transport.TLSClientConfig != nil {
			tlsConfig := transport.TLSClientConfig
			log.Error("TLS Configuration at failure time",
				zap.Int("cert_count", len(tlsConfig.Certificates)),
				zap.Bool("has_root_cas", tlsConfig.RootCAs != nil),
				zap.Bool("insecure_skip_verify", tlsConfig.InsecureSkipVerify),
				zap.Uint16("min_version", tlsConfig.MinVersion),
				zap.Uint16("max_version", tlsConfig.MaxVersion),
			)
		} else {
			log.Error("No TLS configuration found in HTTP client")
		}

		return nil, err
	}
	return res.Body()
}

func (c *Client) SendPostRequest(relativeURI string, body io.Reader) ([]byte, error) {
	uri := fmt.Sprintf("%s%s%s", c.baseURL, c.getPrefix(), relativeURI)
	return c.httpClient.WithTimeout(c.timeout).SendRequest(c.lifecycleCtx, uri, http.MethodPost, body, ErrPDClientRequestFailed, distro.R().PD)
}
