# Go UDP VPN

A lightweight, encrypted Layer 3 VPN written in Go for Linux. It uses Linux `TUN` interfaces (`/dev/net/tun`), UDP sockets, and **AES-256-GCM** authenticated encryption to tunnel IPv4 traffic between a client and a server.

## Features

- **Layer 3 Tunneling**: Creates and configures a virtual `tun0` network interface (`10.0.0.1/24` on the server, `10.0.0.2/24` on the client, MTU `1400`) via Netlink.
- **AES-256-GCM Encryption**: Encrypts and authenticates every packet sent over UDP with a random nonce per packet.
- **Automatic Server NAT**: Enables kernel IPv4 forwarding (`/proc/sys/net/ipv4/ip_forward`) and configures `iptables` `MASQUERADE` on the server's default outbound interface.
- **Automatic Client Routing & Cleanup**:
  - Adds a `/32` bypass route for the VPN server IP via the existing default gateway to prevent routing loops.
  - Routes all IPv4 traffic (`0.0.0.0/1` and `128.0.0.0/1`) through `tun0`.
  - Automatically removes the `/32` bypass route on exit (`SIGINT`/`SIGTERM`).

## Prerequisites

- **OS**: Linux (requires `/dev/net/tun` and Netlink support)
- **Privileges**: Root privileges (`sudo`) are required to create `TUN` interfaces, modify routing tables, and configure `iptables`.
- **Dependencies**:
  - Go 1.26+ (to build from source)
  - `iptables` (required on the server for NAT masquerading)

## Build

Clone the repository and build the binary:

```bash
go build -o vpn .
```

## Configuration

Both the client and server require a shared 32-byte (64-character hex) key for AES-256-GCM encryption, provided via the `KEY` environment variable or a `.env` file in the working directory.

1. Generate a random 32-byte hex key:
   ```bash
   openssl rand -hex 32
   ```

2. Create a `.env` file on both the server and the client with the same key:
   ```env
   KEY=your_64_character_hex_key_here
   ```
   *(Make sure not to commit your `.env` file to version control!)*

## Usage

### 1. Start the Server

Run the VPN in `server` mode on your remote host (listens on UDP port `7646` by default):

```bash
sudo ./vpn -mode=server
```

Make sure UDP port `7646` is open in your server's firewall.

### 2. Start the Client

Run the VPN in `client` mode on your local machine, specifying the server's public IP and port:

```bash
sudo ./vpn -mode=client -server=<SERVER_IP>:7646
```

To stop the client, press `Ctrl+C`. The `tun0` interface and the `/32` server bypass route will be cleaned up automatically.

### Command-Line Flags

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-mode` | *(required)* | Mode to run: `server` or `client` |
| `-server` | `127.0.0.1:7646` | Server address (`host:port`) when running in `client` mode |

## Architecture Overview

| Component | File | Description |
| :--- | :--- | :--- |
| Entrypoint, TUN & Crypto | `main.go` | CLI parsing, `.env` loader, `tun0` creation/configuration, and AES-256-GCM encrypt/decrypt helpers |
| VPN Server | `server.go` | Configures `tun0` (`10.0.0.1/24`), enables IPv4 forwarding + `iptables` NAT, and forwards packets between UDP `:7646` and `tun0` |
| VPN Client | `client.go` | Configures `tun0` (`10.0.0.2/24`), sets up `/32` server bypass and `0.0.0.0/1` + `128.0.0.0/1` tunnel routes, forwards packets, and cleans up routes on exit |
