module github.com/tailscale/wireguard-go/tsasm/amd64/chacha20poly1305/_asm

go 1.25.0

require github.com/mmcloughlin/avo v0.6.0

require (
	github.com/tailscale/wireguard-go v0.0.0
	golang.org/x/mod v0.39.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
)

replace github.com/tailscale/wireguard-go => ../../../..
