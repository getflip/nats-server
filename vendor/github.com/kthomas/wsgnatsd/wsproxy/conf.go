package wsproxy

import (
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/kthomas/nats-server/v2/conf"
	"github.com/kthomas/nats-server/v2/logger"
)

type Opts struct {
	CaFile             string
	CertFile           string
	Debug              bool
	KeyFile            string
	Logger             *logger.Logger
	RemoteNatsHostPort string
	NatsHostPort       string
	TextFrames         bool
	Trace              bool
	WSHostPort         string

	// when true, the authorization http header provided to the websocket request in the form `bearer: <jwt>` is implicitly used to send a CONNECT message to NATS upon successful connection
	WSRequireAuthorization bool
}

func DefaultOpts() Opts {
	var c Opts
	c.RemoteNatsHostPort = "127.0.0.1:4222"
	c.WSHostPort = "127.0.0.1:4221"

	return c
}

func LoadOpts(fp string) (*Opts, error) {
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, fmt.Errorf("error reading configuration file: %v", err)
	}
	return ParseOpts(string(b))
}

func ParseOpts(c string) (*Opts, error) {
	m, err := conf.Parse(c)
	if err != nil {
		return nil, err
	}

	var o Opts
	for k, v := range m {
		k = strings.ToLower(k)
		switch k {
		case "cafile":
			v, err := parseStringValue(k, v)
			if err != nil {
				panic(err)
			}
			o.CaFile = v
		case "certfile":
			v, err := parseStringValue(k, v)
			if err != nil {
				panic(err)
			}
			o.CertFile = v
		case "debug":
			v, err := parseBooleanValue(k, v)
			if err != nil {
				panic(err)
			}
			o.Debug = v
		case "keyfile":
			v, err := parseStringValue(k, v)
			if err != nil {
				panic(err)
			}
			o.KeyFile = v
		case "nats-host":
			v, err := parseStringValue(k, v)
			if err != nil {
				panic(err)
			}
			o.RemoteNatsHostPort = v
		case "textframes":
			v, err := parseBooleanValue(k, v)
			if err != nil {
				panic(err)
			}
			o.TextFrames = v
		case "trace":
			v, err := parseBooleanValue(k, v)
			if err != nil {
				panic(err)
			}
			o.Trace = v
		case "ws-host":
			v, err := parseStringValue(k, v)
			if err != nil {
				panic(err)
			}
			o.WSHostPort = v
		case "ws-require-authorization":
			v, err := parseBooleanValue(k, v)
			if err != nil {
				panic(err)
			}
			o.WSRequireAuthorization = v
		default:
			return nil, fmt.Errorf("error parsing store configuration. Unknown field %q", k)
		}
	}
	return &o, nil
}

func parseIntValue(keyName string, v interface{}) (int, error) {
	i := 0
	var err error
	switch t := v.(type) {
	case int, int8, int16, int32, int64:
		i = t.(int)
	case string:
		i, err = strconv.Atoi(v.(string))
		if err != nil {
			err = fmt.Errorf("error parsing %s option %v as a int", keyName, v)
		}
	default:
		err = fmt.Errorf("unable to parse integer: %v", v)
	}
	return i, err
}

func parseStringValue(keyName string, v interface{}) (string, error) {
	sv, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("error parsing %s option %q", keyName, v)
	}
	return sv, nil
}

func parseBooleanValue(keyname string, v interface{}) (bool, error) {
	switch t := v.(type) {
	case bool:
		return bool(t), nil
	case string:
		sv := v.(string)
		return strings.ToLower(sv) == "true", nil
	default:
		return false, fmt.Errorf("error parsing %s option %q as a boolean", keyname, v)
	}
}
