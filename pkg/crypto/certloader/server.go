// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certloader

import (
	"crypto/tls"

	"github.com/sirupsen/logrus"
)

// TODO
type ServerConfig interface {
	IsMutualTLS() bool
	ServerConfig(base *tls.Config) *tls.Config
}

// TODO
type WatchedServerConfig struct {
	*WatchedConfig
}

// TODO
func NewWatchedServerConfig(log logrus.FieldLogger, caFiles []string, certFile, privkeyFile string) (*WatchedServerConfig, error) {
	cfg, err := NewWatchedConfig(log, caFiles, certFile, privkeyFile)
	if err != nil {
		return nil, err
	}
	return &WatchedServerConfig{cfg}, nil
}

// IsMutualTLS implement ServerConfig.
func (cfg *WatchedServerConfig) IsMutualTLS() bool {
	return cfg.CertificateAuthorityConfigured()
}

// ServerConfig implement ServerConfig.
func (cfg *WatchedServerConfig) ServerConfig(base *tls.Config) *tls.Config {
	// We return a tls.Config having only the GetConfigForClient member set.
	// When a client initialize a TLS handshake, this function will be called
	// and the tls.Config returned by GetConfigForClient will be used. This
	// mechanism allow us to reload the certificates transparently between two
	// clients connections without having to restart the server.
	// See also the discussion at https://github.com/golang/go/issues/16066.
	return &tls.Config{
		GetConfigForClient: func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
			keypair, caCertPool := cfg.KeypairAndCACertPool()
			cfc := base.Clone()
			if cfg.IsMutualTLS() {
				cfc.ClientAuth = tls.RequireAndVerifyClientCert
				cfc.ClientCAs = caCertPool
			}
			cfc.Certificates = []tls.Certificate{*keypair}
			return cfc, nil
		},
	}
}
