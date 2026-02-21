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

package visitor

import (
	"context"
	"fmt"
	"net"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/vnet"
)

// Helper wraps minimal functions needed by plugins.
// This interface is defined here to avoid circular import.
// The actual Helper implementation in client/visitor package will satisfy this interface.
type Helper interface {
	// ConnectServer directly connects to the frp server.
	ConnectServer() (net.Conn, error)
	// RunID returns the run id of current controller.
	RunID() string
}

// PluginContext provides the necessary context and callbacks for visitor plugins.
type PluginContext struct {
	// Name is the unique identifier for this visitor, used for logging and routing.
	Name string

	// Ctx manages the plugin's lifecycle and carries the logger for structured logging.
	Ctx context.Context

	// VnetController manages TUN device routing. May be nil if virtual networking is disabled.
	VnetController *vnet.Controller

	// Helper provides access to frp server connection and run ID.
	Helper Helper

	// SendConnToVisitor sends a connection to the visitor's internal processing queue.
	// Does not return error; failures are handled by closing the connection.
	SendConnToVisitor func(net.Conn)

	// ConnectToProxy creates a visitor connection to the specified proxy.
	// proxyName: target proxy name
	// secretKey: secret key for authentication
	// useEncryption: whether to use encryption (inherited from current visitor config)
	// useCompression: whether to use compression (inherited from current visitor config)
	// Returns a connection that can be used to forward data to the proxy.
	ConnectToProxy func(proxyName, secretKey string, useEncryption, useCompression bool) (net.Conn, error)
}

// Creators is used for create plugins to handle connections.
var creators = make(map[string]CreatorFn)

type CreatorFn func(pluginCtx PluginContext, options v1.VisitorPluginOptions) (Plugin, error)

func Register(name string, fn CreatorFn) {
	if _, exist := creators[name]; exist {
		panic(fmt.Sprintf("plugin [%s] is already registered", name))
	}
	creators[name] = fn
}

func Create(pluginName string, pluginCtx PluginContext, options v1.VisitorPluginOptions) (p Plugin, err error) {
	if fn, ok := creators[pluginName]; ok {
		p, err = fn(pluginCtx, options)
	} else {
		err = fmt.Errorf("plugin [%s] is not registered", pluginName)
	}
	return
}

type Plugin interface {
	Name() string
	Start()
	Close() error
}
