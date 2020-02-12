package wsproxy

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/kthomas/nats-server/v2/server"
)

type NatsServer struct {
	*Opts
	s *server.Server
}

func NewNatsServer(o *Opts) (*NatsServer, error) {
	var ns NatsServer
	ns.Opts = o
	if ns.RemoteNatsHostPort == "" {
		// Create a FlagSet and sets the usage
		fs := flag.NewFlagSet("nats-server", flag.ExitOnError)
		args := GetArgs()
		hasConfig := args.IndexOfFlag("-c") != -1 || args.IndexOfFlag("-config") != -1
		if hasConfig {
			ns.Logger.Noticef("ignoring -a, -addr, -p and -port flags since a config was specified")
		}

		if !hasConfig && args.IndexOfFlag("-a") == -1 && args.IndexOfFlag("-addr") == -1 {
			args = append(args, "-a", "127.0.0.1")
		}

		opts, err := server.ConfigureOptions(
			fs,
			args,
			server.PrintServerAndExit,
			fs.Usage,
			server.PrintTLSHelpAndDie,
		)

		if err != nil {
			msg := fmt.Sprintf("%s\n%s", err.Error(), "embedded NATS s options can be supplied by following a '--' argument with any supported flag.")
			server.PrintAndDie(msg)
		}

		if opts == nil {
			// s was given a help arg
			return nil, nil
		}

		// gnatsd will also handle the signal if this is not set
		opts.NoSigs = true

		s, err := server.NewServer(opts)
		if err != nil {
			return nil, err
		}
		ns.s = s
	}

	return &ns, nil
}

func (s *NatsServer) Start() error {
	s.s.ConfigureLogger()
	go s.s.Start()
	if !s.s.ReadyForConnections(5 * time.Second) {
		return errors.New("unable to start embedded NATS server")
	}
	return nil
}

func (s *NatsServer) Shutdown() {
	if s.s != nil {
		s.s.Shutdown()
	}
}

func (s *NatsServer) HostPort() string {
	if s.s != nil {
		return s.s.Addr().(*net.TCPAddr).String()
	}
	return s.RemoteNatsHostPort
}

func (s *NatsServer) GetURL() string {
	return fmt.Sprintf("nats://%s", s.HostPort())
}

type Args []string

func GetArgs() Args {
	var args Args
	for i, a := range os.Args {
		if a == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	return args
}

func (a Args) GetFlag(v string) string {
	idx := a.IndexOfFlag(v)
	if idx != -1 && len(a) >= idx+1 {
		return a[idx+1]
	}
	return ""
}

func (a Args) IndexOfFlag(v string) int {
	for i, e := range a {
		if v == e {
			return i
		}
	}
	return -1
}
