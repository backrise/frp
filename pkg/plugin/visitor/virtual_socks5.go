// Copyright 2025 The frp Authors
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

//go:build !frps

package visitor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"

	libio "github.com/fatedier/golib/io"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/util/xlog"
)

const (
	modeSocks5Route   = "socks5_route"
	modeUnpackForward = "unpack_forward"
)

func init() {
	Register(v1.VisitorPluginVirtualSocks5, NewVirtualSocks5Plugin)
}

type VirtualSocks5Plugin struct {
	pluginCtx PluginContext
	opts      *v1.VirtualSocks5VisitorPluginOptions

	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc

	// Connection counter for monitoring
	connCount int64
}

func NewVirtualSocks5Plugin(pluginCtx PluginContext, options v1.VisitorPluginOptions) (Plugin, error) {
	opts := options.(*v1.VirtualSocks5VisitorPluginOptions)

	if opts.ListenAddr == "" {
		return nil, errors.New("listenAddr is required")
	}

	if opts.Mode != modeSocks5Route && opts.Mode != modeUnpackForward {
		return nil, fmt.Errorf("invalid mode: %s, must be %s or %s", opts.Mode, modeSocks5Route, modeUnpackForward)
	}

	ctx, cancel := context.WithCancel(pluginCtx.Ctx)

	return &VirtualSocks5Plugin{
		pluginCtx: pluginCtx,
		opts:      opts,
		ctx:       ctx,
		cancel:    cancel,
	}, nil
}

func (p *VirtualSocks5Plugin) Name() string {
	return v1.VisitorPluginVirtualSocks5
}

func (p *VirtualSocks5Plugin) Start() {
	xl := xlog.FromContextSafe(p.pluginCtx.Ctx)
	xl.Infof("starting VirtualSocks5Plugin for visitor [%s], listening on %s, mode: %s",
		p.pluginCtx.Name, p.opts.ListenAddr, p.opts.Mode)

	ln, err := net.Listen("tcp", p.opts.ListenAddr)
	if err != nil {
		xl.Errorf("failed to listen on %s: %v", p.opts.ListenAddr, err)
		return
	}
	p.listener = ln

	go p.acceptLoop()
}

func (p *VirtualSocks5Plugin) acceptLoop() {
	xl := xlog.FromContextSafe(p.ctx)
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.ctx.Done():
				xl.Infof("VirtualSocks5Plugin listener closed for visitor [%s]", p.pluginCtx.Name)
				return
			default:
				xl.Warnf("accept error: %v", err)
				continue
			}
		}

		atomic.AddInt64(&p.connCount, 1)
		go p.handleConn(conn)
	}
}

func (p *VirtualSocks5Plugin) handleConn(conn net.Conn) {
	defer func() {
		atomic.AddInt64(&p.connCount, -1)
		conn.Close()
	}()

	xl := xlog.FromContextSafe(p.ctx)
	xl.Infof("[virtual_socks5] new connection from %s", conn.RemoteAddr())

	// Parse SOCKS5 authentication (username + password; curl sends user:pass as two fields)
	username, password, err := p.parseSocks5Auth(conn)
	if err != nil {
		xl.Warnf("[virtual_socks5] SOCKS5 auth failed: %v", err)
		return
	}
	// Build userinfo: if password set, treat as "name:key" (e.g. curl socks5://name:key@host)
	userinfo := username
	if password != "" {
		userinfo = username + ":" + password
	}
	xl.Infof("[virtual_socks5] auth ok, userinfo=%s", trunct(userinfo))

	// Extended userinfo: FRP_NAME:FRP_KEY[:SOCKS_USER[:SOCKS_PASS]]
	frpName, frpKey, socksUser, socksPass, err := parseExtendedUserinfo(userinfo)
	if err != nil {
		xl.Warnf("[virtual_socks5] parseExtendedUserinfo failed: %v", err)
		p.sendSocks5Error(conn, 0x01)
		return
	}

	// Create connection to proxy (FRP routing)
	proxyConn, err := p.pluginCtx.ConnectToProxy(frpName, frpKey, false, false)
	if err != nil {
		xl.Warnf("[virtual_socks5] ConnectToProxy [%s] failed: %v", frpName, err)
		p.sendSocks5Error(conn, 0x01)
		return
	}
	defer proxyConn.Close()
	xl.Infof("[virtual_socks5] connected to proxy [%s], mode=%s", frpName, p.opts.Mode)

	// Handle based on mode
	if p.opts.Mode == modeSocks5Route {
		p.handleSocks5RouteMode(conn, proxyConn, frpName, frpKey, socksUser, socksPass)
	} else {
		p.handleUnpackForwardMode(conn, proxyConn)
	}
}

func (p *VirtualSocks5Plugin) parseSocks5Auth(conn net.Conn) (username, password string, err error) {
	xl := xlog.FromContextSafe(p.ctx)
	// Read SOCKS5 greeting
	buf := make([]byte, 2)
	if _, err = io.ReadFull(conn, buf); err != nil {
		xl.Warnf("[virtual_socks5] parseSocks5Auth: read greeting failed: %v", err)
		return "", "", fmt.Errorf("read greeting: %v", err)
	}

	if buf[0] != 0x05 {
		xl.Warnf("[virtual_socks5] parseSocks5Auth: invalid SOCKS ver %d", buf[0])
		return "", "", fmt.Errorf("invalid SOCKS version: %d", buf[0])
	}
	xl.Infof("[virtual_socks5] parseSocks5Auth: greeting ok, nmethods=%d", buf[1])

	nMethods := int(buf[1])
	methods := make([]byte, nMethods)
	if _, err = io.ReadFull(conn, methods); err != nil {
		return "", "", fmt.Errorf("read methods: %v", err)
	}

	// Check if username/password authentication is supported
	hasAuth := false
	for _, m := range methods {
		if m == 0x02 { // Username/Password authentication
			hasAuth = true
			break
		}
	}

	if !hasAuth {
		// No auth method, reject
		conn.Write([]byte{0x05, 0xFF}) // No acceptable methods
		return "", "", fmt.Errorf("username/password authentication not supported")
	}

	// Send method selection: username/password
	if _, err = conn.Write([]byte{0x05, 0x02}); err != nil {
		return "", "", fmt.Errorf("write method selection: %v", err)
	}

	// Read username/password
	authBuf := make([]byte, 2)
	if _, err = io.ReadFull(conn, authBuf); err != nil {
		return "", "", fmt.Errorf("read auth header: %v", err)
	}

	if authBuf[0] != 0x01 {
		return "", "", fmt.Errorf("invalid auth version: %d", authBuf[0])
	}

	usernameLen := int(authBuf[1])
	usernameBytes := make([]byte, usernameLen)
	if _, err = io.ReadFull(conn, usernameBytes); err != nil {
		return "", "", fmt.Errorf("read username: %v", err)
	}

	passwordLenBuf := make([]byte, 1)
	if _, err = io.ReadFull(conn, passwordLenBuf); err != nil {
		return "", "", fmt.Errorf("read password length: %v", err)
	}

	passwordLen := int(passwordLenBuf[0])
	passwordBytes := make([]byte, passwordLen)
	if _, err = io.ReadFull(conn, passwordBytes); err != nil {
		return "", "", fmt.Errorf("read password: %v", err)
	}

	username = string(usernameBytes)
	password = string(passwordBytes)

	// Send auth success
	if _, err = conn.Write([]byte{0x01, 0x00}); err != nil {
		xl.Warnf("[virtual_socks5] parseSocks5Auth: write auth success failed: %v", err)
		return "", "", fmt.Errorf("write auth success: %v", err)
	}
	xl.Infof("[virtual_socks5] parseSocks5Auth: sent auth success to client")
	return username, password, nil
}

func (p *VirtualSocks5Plugin) handleSocks5RouteMode(clientConn, proxyConn net.Conn, frpName, frpKey, socksUser, socksPass string) {
	xl := xlog.FromContextSafe(p.ctx)

	// Server-side socks5 expects full handshake. Do greeting + optional auth, then Join.
	xl.Infof("[virtual_socks5] socks5_route: send greeting to proxy")
	greeting := []byte{0x05, 0x02, 0x00, 0x02}
	if _, err := proxyConn.Write(greeting); err != nil {
		xl.Warnf("[virtual_socks5] socks5_route: write greeting failed: %v", err)
		return
	}

	xl.Infof("[virtual_socks5] socks5_route: read method selection from proxy")
	methodResp := make([]byte, 2)
	if _, err := io.ReadFull(proxyConn, methodResp); err != nil {
		xl.Warnf("[virtual_socks5] socks5_route: read method selection failed: %v", err)
		return
	}
	xl.Infof("[virtual_socks5] socks5_route: proxy method response: %02x %02x", methodResp[0], methodResp[1])

	if methodResp[0] != 0x05 {
		xl.Warnf("[virtual_socks5] socks5_route: invalid method response ver %02x", methodResp[0])
		return
	}
	// Use SOCKS_USER/SOCKS_PASS for proxy auth when provided, else frpName/frpKey
	authUser, authPass := socksUser, socksPass
	if authUser == "" {
		authUser = frpName
	}
	if authPass == "" {
		authPass = frpKey
	}
	if methodResp[1] == 0x02 {
		xl.Infof("[virtual_socks5] socks5_route: proxy wants auth, send auth (user=%s)", trunct(authUser))
		u, s := []byte(authUser), []byte(authPass)
		authReq := make([]byte, 0, 3+len(u)+len(s))
		authReq = append(authReq, 0x01, byte(len(u)))
		authReq = append(authReq, u...)
		authReq = append(authReq, byte(len(s)))
		authReq = append(authReq, s...)
		if _, err := proxyConn.Write(authReq); err != nil {
			xl.Warnf("[virtual_socks5] socks5_route: write auth failed: %v", err)
			return
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(proxyConn, authResp); err != nil {
			xl.Warnf("[virtual_socks5] socks5_route: read auth result failed: %v", err)
			return
		}
		xl.Infof("[virtual_socks5] socks5_route: auth result: %02x %02x", authResp[0], authResp[1])
		if authResp[0] != 0x01 || authResp[1] != 0x00 {
			xl.Warnf("[virtual_socks5] socks5_route: proxy auth failed")
			return
		}
	}

	xl.Infof("[virtual_socks5] socks5_route: handshake done, start Join")
	libio.Join(clientConn, proxyConn)
	xl.Infof("[virtual_socks5] socks5_route: Join returned (connection closed)")
}

func (p *VirtualSocks5Plugin) handleUnpackForwardMode(clientConn, proxyConn net.Conn) {
	xl := xlog.FromContextSafe(p.ctx)

	// Read SOCKS5 request
	requestBuf := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, requestBuf); err != nil {
		xl.Debugf("read SOCKS5 request header failed: %v", err)
		return
	}

	if requestBuf[0] != 0x05 {
		p.sendSocks5Error(clientConn, 0x07)
		return
	}

	cmd := requestBuf[1]
	if cmd != 0x01 { // CONNECT command
		p.sendSocks5Error(clientConn, 0x07)
		return
	}

	// Read and parse address
	addrType := requestBuf[3]
	var targetAddr string
	var addrLen int

	switch addrType {
	case 0x01: // IPv4
		addrLen = 4
		addrBytes := make([]byte, addrLen+2)
		if _, err := io.ReadFull(clientConn, addrBytes); err != nil {
			p.sendSocks5Error(clientConn, 0x01)
			return
		}
		ip := net.IP(addrBytes[:4])
		port := int(addrBytes[4])<<8 | int(addrBytes[5])
		targetAddr = fmt.Sprintf("%s:%d", ip.String(), port)
	case 0x03: // Domain name
		addrLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(clientConn, addrLenBuf); err != nil {
			p.sendSocks5Error(clientConn, 0x01)
			return
		}
		addrLen = int(addrLenBuf[0])
		addrBytes := make([]byte, addrLen+2)
		if _, err := io.ReadFull(clientConn, addrBytes); err != nil {
			p.sendSocks5Error(clientConn, 0x01)
			return
		}
		domain := string(addrBytes[:addrLen])
		port := int(addrBytes[addrLen])<<8 | int(addrBytes[addrLen+1])
		targetAddr = fmt.Sprintf("%s:%d", domain, port)
	case 0x04: // IPv6
		addrLen = 16
		addrBytes := make([]byte, addrLen+2)
		if _, err := io.ReadFull(clientConn, addrBytes); err != nil {
			p.sendSocks5Error(clientConn, 0x01)
			return
		}
		ip := net.IP(addrBytes[:16])
		port := int(addrBytes[16])<<8 | int(addrBytes[17])
		targetAddr = fmt.Sprintf("[%s]:%d", ip.String(), port)
	default:
		p.sendSocks5Error(clientConn, 0x08)
		return
	}

	xl.Debugf("SOCKS5 request target: %s", targetAddr)

	// Send SOCKS5 success response
	response := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := clientConn.Write(response); err != nil {
		xl.Debugf("write SOCKS5 response failed: %v", err)
		return
	}

	// Forward raw TCP data (not SOCKS5 protocol)
	xl.Debugf("forwarding raw TCP connection to proxy (target: %s)", targetAddr)
	libio.Join(clientConn, proxyConn)
}

func (p *VirtualSocks5Plugin) sendSocks5Error(conn net.Conn, code byte) {
	// SOCKS5 error response format: VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR + BND.PORT
	response := []byte{0x05, code, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	conn.Write(response)
}

// parseExtendedUserinfo parses the extended userinfo: only segment 1,2 are used for FRP name/key; the rest is passed through to downstream SOCKS5 auth (segment 3 = username, segment 4+ joined by ":" = password).
// Format: FRP_NAME:FRP_KEY[:SOCKS_USER[:SOCKS_PASS[:...]]]
func parseExtendedUserinfo(userinfo string) (frpName, frpKey, socksUser, socksPass string, err error) {
	segments := strings.Split(userinfo, ":")
	if len(segments) < 2 {
		return "", "", "", "", fmt.Errorf("invalid userinfo format: need at least 2 segments (name:key), got %d", len(segments))
	}
	frpName, frpKey = segments[0], segments[1]
	if len(segments) >= 3 {
		socksUser = segments[2]
		socksPass = strings.Join(segments[3:], ":")
	}
	return frpName, frpKey, socksUser, socksPass, nil
}

func trunct(s string) string {
	if len(s) > 16 {
		return s[:16] + "..."
	}
	return s
}

func (p *VirtualSocks5Plugin) Close() error {
	xl := xlog.FromContextSafe(p.pluginCtx.Ctx)
	xl.Infof("closing VirtualSocks5Plugin for visitor [%s]", p.pluginCtx.Name)

	p.cancel()

	if p.listener != nil {
		if err := p.listener.Close(); err != nil {
			xl.Warnf("close listener error: %v", err)
		}
	}

	// Wait for connections to close (with timeout)
	// In production, you might want to add a graceful shutdown mechanism
	xl.Infof("VirtualSocks5Plugin closed for visitor [%s], active connections: %d",
		p.pluginCtx.Name, atomic.LoadInt64(&p.connCount))

	return nil
}
