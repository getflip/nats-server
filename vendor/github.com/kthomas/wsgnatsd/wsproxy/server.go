package wsproxy

import (
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	selfsignedcert "github.com/kthomas/go-self-signed-cert"
	"github.com/kthomas/nats-server/v2/logger"
)

const bridgeTypeEmbedded = "embedded"
const bridgeTypeRemote = "remote"

var bridge *natsBridge

type natsBridge struct {
	*Opts
	natsServer *NatsServer
	wsServer   *WsServer
}

// ListenAndServe runs a standalone instance of the NATS websocket proxy
func ListenAndServe() {
	main(false)
}

// ListenAndServeEmbedded runs an embedded instance of the NATS websocket proxy
func ListenAndServeEmbedded() {
	main(true)
}

func main(embedded bool) {
	o, err := parseFlags(embedded)
	if err != nil {
		panic(err)
	}
	o.Logger = logger.NewStdLogger(true, o.Debug, o.Trace, true, true)

	bridge, err = newBridge(o)
	if err != nil {
		o.Logger.Errorf("Failed to create sub-systems: %v\n")
		panic(err)
	}

	if bridge == nil {
		// prob help option
		return
	}

	if err := bridge.start(); err != nil {
		o.Logger.Errorf("Failed to start sub-systems: %v\n")
		bridge.shutdown()
		panic(err)
	}

	handleSignals()

	if bridge != nil {
		runtime.Goexit()
	}
}

func newBridge(opts *Opts) (*natsBridge, error) {
	var err error

	var natsServer *NatsServer
	var wsServer *WsServer

	natsServer, err = NewNatsServer(opts)
	if err != nil {
		return nil, err
	}

	wsServer, err = NewWsServer(opts)
	if err != nil {
		return nil, err
	}

	return &natsBridge{
		opts,
		natsServer,
		wsServer,
	}, nil
}

func (b *natsBridge) start() error {
	b.wsServer.NatsHostPort = b.natsServer.HostPort()
	bridge.Opts.Logger.Noticef("natsBridge using NATS server %s", b.natsServer.HostPort())

	if err := b.wsServer.Start(); err != nil {
		return err
	}

	return nil
}

func (b *natsBridge) shutdown() {
	b.wsServer.Shutdown()
	b.natsServer.Shutdown()
}

func natsBridgeArgs() []string {
	inlineArgs := -1
	for i, a := range os.Args {
		if a == "--" {
			inlineArgs = i
			break
		}
	}

	var args []string
	if inlineArgs == -1 {
		args = os.Args[1:]
	} else {
		args = os.Args[1 : inlineArgs+1]
	}

	return args
}

func parseFlags(embedded bool) (*Opts, error) {
	flagsetName := "wsgnatsd"
	flagsetErrHandling := flag.ExitOnError
	if embedded {
		flagsetName = ""
		flagsetErrHandling = flag.ContinueOnError
	}
	opts := flag.NewFlagSet(flagsetName, flagsetErrHandling)

	var confFile string
	c := DefaultOpts()
	opts.StringVar(&confFile, "c", "", "configuration file")
	opts.StringVar(&c.WSHostPort, "h", c.WSHostPort, "ws-host - default is 127.0.0.1:4221")
	opts.BoolVar(&c.WSRequireAuthorization, "a", c.WSRequireAuthorization, "ws-require-authorization - when true, the authorization http header provided to the websocket request in the form `bearer: <jwt>` is implicitly used to send a CONNECT message to NATS")
	opts.StringVar(&c.RemoteNatsHostPort, "nh", c.RemoteNatsHostPort, "nats-host - disables embedded NATS and proxies requests to the specified hostport")
	opts.StringVar(&c.CaFile, "ca", c.CaFile, "cafile - ca certificate file for ws server")
	opts.StringVar(&c.CertFile, "cert", c.CertFile, "certfile - certificate file for ws server")
	opts.StringVar(&c.KeyFile, "key", c.KeyFile, "keyfile - certificate key for ws server")
	opts.BoolVar(&c.TextFrames, "text", c.TextFrames, "textframes - use text websocket frames")
	opts.BoolVar(&c.Debug, "D", c.Debug, "debug - enable debugging output")
	opts.BoolVar(&c.Trace, "V", c.Trace, "trace - enable tracing output")

	a := natsBridgeArgs()
	if err := opts.Parse(a); err != nil {
		if !embedded {
			opts.Usage()
			os.Exit(0)
		}
	}

	if confFile != "" && len(a) > 0 {
		return nil, errors.New("no additional flags for the bridge can be specified in the command")
	}

	if confFile != "" {
		fc, err := LoadOpts(confFile)
		if err != nil {
			return nil, err
		}
		c = *fc
	}

	if c.KeyFile != "" || c.CertFile != "" {
		if c.KeyFile == "" || c.CertFile == "" {
			panic("if -cert or -key is specified, both must be supplied")
		}
	} else {
		privKeyPath, certPath, err := selfsignedcert.GenerateToDisk([]string{})
		if err != nil {
			log.Panicf("failed to generate self-signed certificate; %s", err.Error())
		}
		c.KeyFile = *privKeyPath
		c.CertFile = *certPath
	}

	return &c, nil
}

// handle signals so we can orderly shutdown
func handleSignals() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT)
	go func() {
		for sig := range c {
			switch sig {
			case syscall.SIGINT:
				bridge.shutdown()
				os.Exit(0)
			}
		}
	}()
}
