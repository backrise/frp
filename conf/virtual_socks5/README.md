# Virtual SOCKS5 Plugin

## Overview

The virtual_socks5 plugin enables SOCKS5 proxy functionality over FRP tunnels, allowing clients to access SOCKS5 proxy services through encrypted connections without directly exposing proxy ports.

## Architecture

```
Client Browser → SOCKS5 (virtual_socks5) → FRP Client (visitor) → FRP Server → FRP Client (proxy) → Real SOCKS5 Server
```

## How It Works

1. **Virtual SOCKS5 Listener**: The visitor plugin creates a local SOCKS5 proxy server
2. **Connection Interception**: Incoming SOCKS5 connections are captured and encrypted
3. **FRP Tunnel Transport**: Connections are forwarded through FRP's secure tunnel
4. **Proxy Resolution**: At the remote end, connections emerge from the proxy plugin
5. **SOCKS5 Processing**: Remote connections can then access actual network resources

## Plugin Modes

### socks5_route Mode (Default)
- **Entire SOCKS5 forwarding**: Complete SOCKS5 protocol data is forwarded through the tunnel
- **Use with socks5 plugin**: Must pair with standard socks5 plugin on proxy side
- **Simple deployment**: No protocol inspection or modification

### unpack_forward Mode
- **SOCKS5 unpacking**: Parses SOCKS5 requests to extract target addresses
- **Raw TCP forwarding**: Establishes direct TCP connections to target services
- **Flexible routing**: Can forward to any type of proxy, not just socks5
- **Advanced usage**: Suitable for complex routing scenarios

## Extended Userinfo (client auth)

The client connects to virtual_socks5 with SOCKS5 username/password. The **username** uses an extended format; the password is ignored for parsing.

- **Segments 1 and 2** are used only for FRP routing: `FRP_NAME:FRP_KEY` (connect to proxy and authenticate to FRP).
- **Segment 3 and beyond** are passed through to the downstream SOCKS5 (in socks5_route mode): segment 3 = username, segments 4+ joined with `:` = password. If only 2 segments are given, FRP name/key are sent to the downstream SOCKS5 for auth.

Examples:
- `proxy1:secret` → FRP proxy "proxy1" with key "secret"; downstream auth uses proxy1/secret.
- `proxy1:secret:myuser` → same FRP; downstream auth username "myuser", password empty.
- `proxy1:secret:myuser:mypass` → downstream auth "myuser"/"mypass".
- `proxy1:secret:u:p:x` → downstream auth username "u", password "p:x".

## Configuration Examples

### FRP Server (frps.toml)
```toml
bindPort = 7000
```

### SOCKS5 Proxy Provider (proxy.toml)
```toml
serverAddr = "127.0.0.1"
serverPort = 7000

# Optional: STUN server for XTCP (default: stun.easyvoip.com:3478)
# natHoleStunServer = "stun.easyvoip.com:3478"

[[proxies]]
name = "socks5_proxy"
type = "xtcp"
secretKey = "abc123"

[proxies.plugin]
type = "socks5"
# Optional authentication
# username = "socks_user"
# password = "socks_pass"
```

### Virtual SOCKS5 Client (visitor.toml)
Use **XTCP**; the proxy is chosen by client userinfo (name:key) per connection. Set `bindPort = -1`; `serverName`/`secretKey` are for validation only (plugin uses userinfo).
```toml
serverAddr = "127.0.0.1"
serverPort = 7000

# Optional: STUN server for XTCP (default: stun.easyvoip.com:3478)
# natHoleStunServer = "stun.easyvoip.com:3478"

[[visitors]]
name = "local_socks5"
type = "xtcp"
serverName = "_"
secretKey = "_"
bindPort = -1

[visitors.plugin]
type = "virtual_socks5"
listenAddr = "127.0.0.1:21080"
mode = "socks5_route"  # Forward entire SOCKS5 connections
```

## Dynamic proxy by userinfo (XTCP)

The visitor uses **XTCP** and supports **delay-specified proxy**: each client connection sends `name:key` in SOCKS5 userinfo (e.g. `socks5_proxy:abc123`), and the plugin calls `ConnectToProxy(name, key)` for that proxy. The XTCP visitor will create or reuse a NAT hole session per (proxyName, secretKey). You can connect to different proxies without changing the visitor config. Set `bindPort = -1`; `serverName`/`secretKey` can be placeholders (e.g. `"_"`) for validation—the plugin uses userinfo, not these.

## NAT / STUN (XTCP)

Both proxy and visitor use XTCP; set `natHoleStunServer` in the frpc config if needed:

```toml
# Optional: STUN server for XTCP (default: stun.easyvoip.com:3478)
natHoleStunServer = "stun.easyvoip.com:3478"
```

**TURN**: XTCP uses only STUN (no TURN). If hole punching fails, the connection fails.

## Security Considerations

- **Authentication**: Supports username/password authentication
- **Encryption**: All data is encrypted during FRP transport
- **Secret Keys**: Use strong secret keys for proxy authentication
- **Local Binding**: Default `bindPort = -1` prevents direct external access

## Use Cases

- **Secure Remote Access**: Access SOCKS5 services through encrypted tunnels
- **Bypass Network Restrictions**: Use SOCKS5 proxy over FRP in restrictive environments
- **Distributed Proxy Networks**: Build proxy chains across multiple FRP nodes
- **Development Testing**: Test SOCKS5 client applications in controlled environments