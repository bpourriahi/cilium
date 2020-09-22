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
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/lock"
)

// TODO
type WatchedConfig struct {
	log         logrus.FieldLogger
	caFiles     []string
	certFile    string
	privkeyFile string
	stop        chan struct{}
	mu          lock.Mutex
	caCertPool  *x509.CertPool
	keypair     *tls.Certificate
}

var (
	// TODO
	ErrCertWithoutPrivkey = errors.New("certificate and private key are both required, but only the certificate was provided")
	// TODO
	ErrPrivkeyWithoutCert = errors.New("certificate and private key are both required, but only the private key was provided")
)

// TODO
func NewWatchedConfig(log logrus.FieldLogger, caFiles []string, certFile, privkeyFile string) (*WatchedConfig, error) {
	if certFile != "" && privkeyFile == "" {
		return nil, ErrCertWithoutPrivkey
	}
	if certFile == "" && privkeyFile != "" {
		return nil, ErrPrivkeyWithoutCert
	}

	cfg := &WatchedConfig{
		log:         log,
		caFiles:     caFiles,
		certFile:    certFile,
		privkeyFile: privkeyFile,
	}

	// load the files for the first time before starting the watcher and update
	// goroutine.
	if err := cfg.Reload(); err != nil {
		return nil, err
	}
	if err := cfg.Watch(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Watch initialize the WatchedConfig files watcher and update goroutine.
func (cfg *WatchedConfig) Watch() error {
	// FIXME: use sync.Once in order to run exactly one watcher.
	// file watcher setup.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("Failed to create fsnotify watcher: %s", err)
	}
	for _, path := range cfg.caFiles {
		if err := watcher.Add(path); err != nil {
			watcher.Close()
			return fmt.Errorf("Failed to add %q to fsnotify watcher: %s", path, err)
		}
	}
	if cfg.certFile != "" {
		if err := watcher.Add(cfg.certFile); err != nil {
			watcher.Close()
			return fmt.Errorf("Failed to add %q to fsnotify watcher: %s", cfg.certFile, err)
		}
	}
	if cfg.privkeyFile != "" {
		if err := watcher.Add(cfg.privkeyFile); err != nil {
			watcher.Close()
			return fmt.Errorf("Failed to add %q to fsnotify watcher: %s", cfg.privkeyFile, err)
		}
	}

	cfg.stop = make(chan struct{})
	go func() {
		defer watcher.Close()
		for {
			select {
			case event := <-watcher.Events:
				cfg.log.Debugf("Received fsnotify event: %+v", event)
				switch event.Op {
				case fsnotify.Create, fsnotify.Write, fsnotify.Chmod, fsnotify.Remove, fsnotify.Rename:
					if err := cfg.Reload(); err != nil {
						cfg.log.WithError(err).Warn("config update failed")
					} else {
						cfg.log.Info("config updated")
					}
				default:
					cfg.log.Warnf("Watcher received unknown event: %s. Ignoring.", event)
				}
			case err := <-watcher.Errors:
				cfg.log.WithError(err).Warn("Watcher received an error")
			case <-cfg.stop:
				cfg.log.Info("Stopping")
				return
			}
		}
	}()

	return nil
}

// CertificateAuthorityConfigured returns true when the WatchedConfig has at
// least one CA file, false otherwise.
func (cfg *WatchedConfig) CertificateAuthorityConfigured() bool {
	return len(cfg.caFiles) > 0
}

// KeypairConfigured returns true when the WatchedConfig contains both a
// certificate and its private key, false otherwise.
func (cfg *WatchedConfig) KeypairConfigured() bool {
	return cfg.certFile != "" && cfg.privkeyFile != ""
}

// Reload read the WatchedConfig files.
func (cfg *WatchedConfig) Reload() error {
	cfg.mu.Lock()
	defer cfg.mu.Unlock()

	// CA update
	if cfg.CertificateAuthorityConfigured() {
		if len(cfg.caFiles) > 0 {
			caCertPool := x509.NewCertPool()
			for _, path := range cfg.caFiles {
				pem, err := ioutil.ReadFile(path)
				if err != nil {
					return fmt.Errorf("failed to load cert %q: %s", path, err)
				}
				if ok := caCertPool.AppendCertsFromPEM(pem); !ok {
					return fmt.Errorf("failed to load cert %q: must be PEM encoded", path)
				}
			}
			cfg.caCertPool = caCertPool
		} else {
			caCertPool, err := x509.SystemCertPool()
			if err != nil {
				return fmt.Errorf("failed to load the system ca certificates: %s", err)
			}
			cfg.caCertPool = caCertPool
		}
	}

	// keypair update
	if cfg.KeypairConfigured() {
		keypair, err := tls.LoadX509KeyPair(cfg.certFile, cfg.privkeyFile)
		if err != nil {
			return fmt.Errorf("failed to load keypair: %s", err)
		}
		cfg.keypair = &keypair
	}

	return nil
}

// KeypairAndCA returns both the configured keypair and CAs.
func (cfg *WatchedConfig) KeypairAndCACertPool() (*tls.Certificate, *x509.CertPool) {
	cfg.mu.Lock()
	keypair := cfg.keypair
	caCertPool := cfg.caCertPool
	cfg.mu.Unlock()
	return keypair, caCertPool
}

// Stop watching the WatchedConfig files.
func (cfg *WatchedConfig) Stop() {
	if cfg.stop != nil {
		close(cfg.stop)
	}
}
