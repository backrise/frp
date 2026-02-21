// Copyright 2017 fatedier, fatedier@gmail.com
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

package visitor

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	libio "github.com/fatedier/golib/io"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	plugin "github.com/fatedier/frp/pkg/plugin/visitor"
	"github.com/fatedier/frp/pkg/transport"
	netpkg "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/util/util"
	"github.com/fatedier/frp/pkg/util/xlog"
	"github.com/fatedier/frp/pkg/vnet"
)

// Helper wraps some functions for visitor to use.
type Helper interface {
	// ConnectServer directly connects to the frp server.
	ConnectServer() (net.Conn, error)
	// TransferConn transfers the connection to another visitor.
	TransferConn(string, net.Conn) error
	// MsgTransporter returns the message transporter that is used to send and receive messages
	// to the frp server through the controller.
	MsgTransporter() transport.MessageTransporter
	// VNetController returns the vnet controller that is used to manage the virtual network.
	VNetController() *vnet.Controller
	// RunID returns the run id of current controller.
	RunID() string
}

// ProxyConnOpener opens a connection to a proxy. Kept as separate interface for easier extension.
type ProxyConnOpener interface {
	OpenConnToProxy(proxyName, secretKey string, useEncryption, useCompression bool) (net.Conn, error)
}

// Visitor is used for forward traffics from local port to remote service.
// ProxyConnOpener is embedded so all visitors implement it; extend ProxyConnOpener without touching Visitor.
type Visitor interface {
	Run() error
	AcceptConn(conn net.Conn) error
	Close()
	ProxyConnOpener
}

func NewVisitor(
	ctx context.Context,
	cfg v1.VisitorConfigurer,
	clientCfg *v1.ClientCommonConfig,
	helper Helper,
) (Visitor, error) {
	xl := xlog.FromContextSafe(ctx).Spawn().AppendPrefix(cfg.GetBaseConfig().Name)
	ctx = xlog.NewContext(ctx, xl)
	var visitor Visitor
	baseVisitor := BaseVisitor{
		clientCfg:  clientCfg,
		helper:     helper,
		ctx:        ctx,
		internalLn: netpkg.NewInternalListener(),
	}
	switch cfg := cfg.(type) {
	case *v1.STCPVisitorConfig:
		visitor = &STCPVisitor{
			BaseVisitor: &baseVisitor,
			cfg:         cfg,
		}
	case *v1.XTCPVisitorConfig:
		visitor = &XTCPVisitor{
			BaseVisitor:     &baseVisitor,
			cfg:             cfg,
			startTunnelCh:   make(chan struct{}),
			dynamicSessions: make(map[string]TunnelSession),
		}
	case *v1.SUDPVisitorConfig:
		visitor = &SUDPVisitor{
			BaseVisitor:  &baseVisitor,
			cfg:          cfg,
			checkCloseCh: make(chan struct{}),
		}
	}
	if cfg.GetBaseConfig().Plugin.Type != "" {
		p, err := plugin.Create(
			cfg.GetBaseConfig().Plugin.Type,
			plugin.PluginContext{
				Name:           cfg.GetBaseConfig().Name,
				Ctx:            ctx,
				VnetController: helper.VNetController(),
				Helper:         helper,
				SendConnToVisitor: func(conn net.Conn) {
					_ = baseVisitor.AcceptConn(conn)
				},
				ConnectToProxy: visitor.OpenConnToProxy,
			},
			cfg.GetBaseConfig().Plugin.VisitorPluginOptions,
		)
		if err != nil {
			return nil, err
		}
		baseVisitor.plugin = p
	}
	return visitor, nil
}

type BaseVisitor struct {
	clientCfg  *v1.ClientCommonConfig
	helper     Helper
	l          net.Listener
	internalLn *netpkg.InternalListener
	plugin     plugin.Plugin

	mu  sync.RWMutex
	ctx context.Context
}

func (v *BaseVisitor) AcceptConn(conn net.Conn) error {
	return v.internalLn.PutConn(conn)
}

func (v *BaseVisitor) Close() {
	if v.l != nil {
		v.l.Close()
	}
	if v.internalLn != nil {
		v.internalLn.Close()
	}
	if v.plugin != nil {
		v.plugin.Close()
	}
}

// createVisitorConnToProxy creates a visitor connection to the specified proxy.
// This function encapsulates the logic for creating a visitor connection,
// similar to STCPVisitor.handleConn but for dynamic proxy connections.
func createVisitorConnToProxy(
	helper Helper,
	proxyName, secretKey string,
	useEncryption, useCompression bool,
) (net.Conn, error) {
	// Connect to frps
	visitorConn, err := helper.ConnectServer()
	if err != nil {
		return nil, fmt.Errorf("connect to server error: %v", err)
	}

	// Send NewVisitorConn message
	now := time.Now().Unix()
	newVisitorConnMsg := &msg.NewVisitorConn{
		RunID:          helper.RunID(),
		ProxyName:      proxyName,
		SignKey:        util.GetAuthKey(secretKey, now),
		Timestamp:      now,
		UseEncryption:  useEncryption,
		UseCompression: useCompression,
	}
	if err := msg.WriteMsg(visitorConn, newVisitorConnMsg); err != nil {
		visitorConn.Close()
		return nil, fmt.Errorf("send newVisitorConnMsg error: %v", err)
	}

	// Receive response
	var newVisitorConnRespMsg msg.NewVisitorConnResp
	visitorConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := msg.ReadMsgInto(visitorConn, &newVisitorConnRespMsg); err != nil {
		visitorConn.Close()
		return nil, fmt.Errorf("read newVisitorConnRespMsg error: %v", err)
	}
	visitorConn.SetReadDeadline(time.Time{})

	if newVisitorConnRespMsg.Error != "" {
		visitorConn.Close()
		return nil, fmt.Errorf("start new visitor connection error: %s", newVisitorConnRespMsg.Error)
	}

	// Wrap with encryption/compression if needed
	var remote io.ReadWriteCloser = visitorConn
	if useEncryption {
		remote, err = libio.WithEncryption(remote, []byte(secretKey))
		if err != nil {
			visitorConn.Close()
			return nil, fmt.Errorf("create encryption stream error: %v", err)
		}
	}
	if useCompression {
		remote = libio.WithCompression(remote)
	}

	// Return wrapped connection
	return netpkg.WrapReadWriteCloserToConn(remote, visitorConn), nil
}
