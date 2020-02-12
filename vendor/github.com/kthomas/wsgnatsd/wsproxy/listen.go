package wsproxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
)

func hostPort(l net.Listener) string {
	return l.Addr().(*net.TCPAddr).String()
}

func CreateListen(hp string, o *Opts) (net.Listener, error) {
	if o.CertFile != "" {
		return createTlsListen(hp, o)
	}
	return net.Listen("tcp", hp)
}

func makeTLSConfig(o *Opts) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
	if err != nil {
		return nil, err
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	config := tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
	}

	if o.CaFile != "" {
		caCert, err := ioutil.ReadFile(o.CaFile)
		if err != nil {
			log.Fatal(err)
		}
		caPool := x509.NewCertPool()
		if ok := caPool.AppendCertsFromPEM(caCert); !ok {
			return nil, errors.New("error parsing ca cert")
		}
		config.RootCAs = caPool
	}
	return &config, nil
}

func createTlsListen(hp string, o *Opts) (net.Listener, error) {
	tlsConfig, err := makeTLSConfig(o)
	if err != nil {
		return nil, fmt.Errorf("error generating tls config: %v", err)
	}

	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}

	config := tlsConfig.Clone()
	config.ClientAuth = tls.NoClientCert
	config.PreferServerCipherSuites = true
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("error loading tls certs: %v", err)
	}
	return tls.Listen("tcp", hp, config)
}
