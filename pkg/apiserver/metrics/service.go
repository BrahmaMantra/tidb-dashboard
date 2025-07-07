// Copyright 2024 PingCAP, Inc. Licensed under Apache-2.0.

package metrics

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/joomcode/errorx"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/atomic"
	"go.uber.org/fx"
	"golang.org/x/sync/singleflight"

	"github.com/pingcap/tidb-dashboard/pkg/config"
	"github.com/pingcap/tidb-dashboard/pkg/pd"
)

var (
	ErrNS                          = errorx.NewNamespace("error.api.metrics")
	ErrLoadPrometheusAddressFailed = ErrNS.NewType("load_prom_address_failed")
	ErrPrometheusNotFound          = ErrNS.NewType("prom_not_found")
	ErrPrometheusQueryFailed       = ErrNS.NewType("prom_query_failed")
)

const (
	defaultPromQueryTimeout = time.Second * 30
)

type ServiceParams struct {
	fx.In
	Config     *config.Config
	EtcdClient *clientv3.Client
	PDClient   *pd.Client
}

type Service struct {
	params       ServiceParams
	lifecycleCtx context.Context

	promRequestGroup singleflight.Group
	promAddressCache atomic.Value
	httpClient       *http.Client
}

func NewService(lc fx.Lifecycle, p ServiceParams) *Service {
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	s := &Service{
		params: p,
		httpClient: &http.Client{
			Transport: &http.Transport{
				DialTLS: func(network, addr string) (net.Conn, error) {
					conn, err := tls.Dial(network, addr, tlsConfig)
					return conn, err
				},
				TLSClientConfig:   tlsConfig,
				ForceAttemptHTTP2: true,
			},
			Timeout: defaultPromQueryTimeout,
		},
	}

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			s.lifecycleCtx = ctx
			return nil
		},
	})

	return s
}
