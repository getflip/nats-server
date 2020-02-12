package wsproxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/gorilla/websocket"
	"github.com/kthomas/nats-server/v2/logger"
)

type WsServer struct {
	*Opts
	s *http.Server
	l net.Listener
}

func NewWsServer(opts *Opts) (*WsServer, error) {
	var server WsServer
	server.Opts = opts
	return &server, nil
}

func (s *WsServer) Shutdown() {
	if s.s != nil {
		_ = s.s.Shutdown(context.TODO())
	}
}

func (s *WsServer) isTLS() bool {
	return s.CertFile != ""
}

func (s *WsServer) Start() error {
	l, err := CreateListen(s.WSHostPort, s.Opts)
	if err != nil {
		return err
	}
	s.l = l
	s.WSHostPort = hostPort(s.l)

	s.s = &http.Server{
		ErrorLog: log.New(os.Stderr, "s", log.LstdFlags),
		Handler:  http.HandlerFunc(s.handleSession),
	}

	s.Logger.Noticef("Listening for websocket requests on %v\n", s.GetURL())

	frames := "binary"
	if s.TextFrames {
		frames = "text"
	}
	s.Logger.Noticef("Proxy is using %s frames\n", frames)

	go func() {
		if err := s.s.Serve(s.l); err != nil {
			// we orderly shutdown the s?
			if !strings.Contains(err.Error(), "Server closed") {
				s.Logger.Fatalf("wsserver error: %v\n", err)
				panic(err)
			}
		}
		s.s.Handler = nil
		s.s = nil
		s.Logger.Noticef("wsserver stopped\n")
	}()

	return nil
}

var counter uint64

func (s *WsServer) parseBearerToken(r *http.Request) (*string, error) {
	authorization := r.Header.Get("authorization")
	if authorization == "" {
		if s.WSRequireAuthorization {
			return nil, errors.New("no bearer authorization header provided")
		}
		return nil, nil
	}

	hdrprts := strings.Split(authorization, "bearer ")
	if s.WSRequireAuthorization && len(hdrprts) != 2 {
		return nil, errors.New("invalid bearer authorization header provided")
	}

	token := hdrprts[1]
	s.Logger.Debugf("resolved bearer token %s", token)
	return &token, nil
}

func (s *WsServer) handleSession(w http.ResponseWriter, r *http.Request) {
	id := atomic.AddUint64(&counter, 1)
	upgrader := websocket.Upgrader{}
	upgrader.CheckOrigin = func(req *http.Request) bool {
		return true
	}

	token, err := s.parseBearerToken(r)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte(fmt.Sprintf("unauthorized: %v", err)))
	}

	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.Logger.Errorf("failed to upgrade ws connection: %v", err)
		return
	}
	defer c.Close()

	proxy, err := NewProxyWorker(id, c, s.NatsHostPort, s, token)
	if err != nil {
		s.Logger.Errorf("failed to connect to nats: %v", err)
		return
	}
	proxy.Serve()
}

type ProxyWorker struct {
	id          uint64
	bearerToken *string
	done        chan string
	ws          *websocket.Conn
	tcp         net.Conn
	frameType   int
	logger      *logger.Logger
}

func NewProxyWorker(id uint64, ws *websocket.Conn, natsHostPort string, server *WsServer, bearerToken *string) (*ProxyWorker, error) {
	tcp, err := net.Dial("tcp", natsHostPort)
	if err != nil {
		return nil, err
	}

	proxy := &ProxyWorker{
		id:          id,
		bearerToken: bearerToken,
		done:        make(chan string),
		ws:          ws,
		tcp:         tcp,
		logger:      server.Logger,
	}

	if server.TextFrames {
		proxy.frameType = websocket.TextMessage
	} else {
		proxy.frameType = websocket.BinaryMessage
	}

	return proxy, nil
}

func debugFrameType(ft int) string {
	switch ft {
	case websocket.TextMessage:
		return "TEXT"
	case websocket.BinaryMessage:
		return "BIN"
	case websocket.CloseMessage:
		return "CLOSE"
	case websocket.PingMessage:
		return "PING"
	case websocket.PongMessage:
		return "PONG"
	}
	return "?"
}

func PrintProto(a []byte) {
	for i, v := range a {
		fmt.Printf("%d '%c' %d\n", i, v, v)
	}
}

func parseInfo(proto []byte) map[string]interface{} {
	count := len(proto)
	if count > 5 {
		if (proto[0] == 'I' || proto[0] == 'i') &&
			(proto[1] == 'N' || proto[1] == 'n') &&
			(proto[2] == 'F' || proto[2] == 'f') &&
			(proto[3] == 'O' || proto[3] == 'o') &&
			(proto[4] == ' ' || proto[4] == '\t') &&
			(proto[5] == '{') {

			var infoArg []byte
			for i := range proto {
				if i+1 < count && proto[i] == '\r' && proto[i+1] == '\n' {
					infoArg = proto[5:i]
					break
				}
			}
			info := make(map[string]interface{})
			if err := json.Unmarshal(infoArg, &info); err != nil {
				return nil
			}
			return info
		}
	}
	return nil
}

func (pw *ProxyWorker) tlsRequired(proto []byte) bool {
	tlsRequired := false

	info := parseInfo(proto)
	t := info["tls_required"]
	if t != nil {
		bv, ok := t.(bool)
		if ok {
			tlsRequired = bv
		}
	}
	return tlsRequired
}

func (pw *ProxyWorker) upgrade() error {
	pw.tcp = tls.Client(pw.tcp, &tls.Config{InsecureSkipVerify: true})
	conn := pw.tcp.(*tls.Conn)
	err := conn.Handshake()
	if err != nil {
		pw.logger.Errorf("failed to upgrade websocket connection: %v", err)
		return err
	}
	return nil
}

func (pw *ProxyWorker) authenticate() error {
	cmsg := fmt.Sprintf("CONNECT {\"jwt\":%q,\"verbose\":true,\"pedantic\":true}\r\nPING\r\n", *pw.bearerToken)
	_, err := pw.tcp.Write([]byte(cmsg))
	if err != nil {
		pw.logger.Errorf("failed to send CONNECT message; %v", err)
		return err
	}
	return nil
}

func (pw *ProxyWorker) Serve() {
	go func() {
		for {
			mt, data, err := pw.ws.ReadMessage()
			if err != nil {
				pw.logger.Errorf("ws read: %v", err)
				break
			}
			pw.logger.Tracef("ws [%v] >: %v\n", debugFrameType(mt), string(data))

			if mt == websocket.TextMessage || mt == websocket.BinaryMessage {
				count, err := pw.tcp.Write(data)
				if err != nil {
					pw.logger.Errorf("tcp write: %v", err)
				}
				if count != len(data) {
					pw.logger.Errorf("tcp wrote %d instead of %d bytes", count, len(data))
				}
			}
			if mt == websocket.CloseMessage {
				break
			}
		}
		pw.done <- "done"
	}()

	first := true
	go func() {
		buf := make([]byte, 4096)
		for {
			count, err := pw.tcp.Read(buf)
			if err != nil {
				pw.logger.Errorf("tcp read: %v", err)
				break
			}

			if first {
				first = false
				if pw.tlsRequired(buf[0:count]) {
					err := pw.upgrade()
					if err != nil {
						pw.logger.Errorf("tcp read: %v", err)
						break
					}
				}

				if pw.bearerToken != nil {
					err := pw.authenticate()
					if err != nil {
						pw.logger.Errorf("NATS authorization failed: %v", err)
						break
					}
				}
			}

			pw.logger.Tracef("tcp >: %v\n", string(buf[0:count]))
			err = pw.ws.WriteMessage(pw.frameType, buf[0:count])
			if err != nil {
				pw.logger.Errorf("ws write: %v", err)
				break
			}
		}
		pw.done <- "done"
	}()

	<-pw.done
	pw.tcp.Close()
	pw.ws.Close()
	<-pw.done
	pw.logger.Noticef("ws-nats client [%d] closed", pw.id)
}

func (s *WsServer) GetURL() string {
	protocol := "ws"
	if s.isTLS() {
		protocol = "wss"
	}
	return fmt.Sprintf("%s://%s", protocol, s.WSHostPort)
}
