package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink"
)

func createClientSocket(serverAddrStr string) (*net.UDPConn, *net.UDPAddr, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", serverAddrStr)
	if err != nil {
		return nil, nil, err
	}

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return nil, nil, err
	}

	return conn, serverAddr, nil
}

func setupClientRoutes(tunName string, serverIP net.IP) (*netlink.Route, error) {
	tunLink, err := netlink.LinkByName(tunName)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface %s: %w", tunName, err)
	}

	// 1. Find the current default route (0.0.0.0/0) to get real gateway & interface
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %w", err)
	}

	var defaultGw net.IP
	var defaultLinkIndex int
	for _, r := range routes {
		if r.Dst == nil || r.Dst.IP.Equal(net.IPv4zero) {
			defaultGw = r.Gw
			defaultLinkIndex = r.LinkIndex
			break
		}
	}

	if defaultGw == nil {
		return nil, fmt.Errorf("could not find existing default gateway")
	}

	// 2. Add /32 bypass route for VPN server via the real gateway (prevents infinite loop)
	var bypassRoute *netlink.Route
	if !serverIP.IsLoopback() {
		serverDst := &net.IPNet{IP: serverIP.To4(), Mask: net.CIDRMask(32, 32)}
		bypassRoute = &netlink.Route{
			LinkIndex: defaultLinkIndex,
			Dst:       serverDst,
			Gw:        defaultGw,
		}
		if err := netlink.RouteReplace(bypassRoute); err != nil {
			return nil, fmt.Errorf("failed to add bypass route for server %s: %w", serverIP, err)
		}
	}

	// 3. Route all IPv4 traffic (0.0.0.0/1 and 128.0.0.0/1) through tun0
	for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		_, dst, _ := net.ParseCIDR(cidr)
		route := &netlink.Route{
			LinkIndex: tunLink.Attrs().Index,
			Dst:       dst,
			Gw:        net.ParseIP("10.0.0.1"),
		}
		if err := netlink.RouteReplace(route); err != nil {
			if bypassRoute != nil {
				_ = netlink.RouteDel(bypassRoute)
			}
			return nil, fmt.Errorf("failed to add route %s: %w", cidr, err)
		}
	}

	return bypassRoute, nil
}

func runClient(serverAddrStr string) {
	keyStr := os.Getenv("KEY")
	key, err := hex.DecodeString(keyStr)
	if err != nil || len(key) != 32 {
		log.Fatalf("Invalid KEY (expected 64-char hex string for 32-byte AES-256 key): %v", err)
	}

	tun, ifName, err := createTun("tun0")
	if err != nil {
		log.Fatalf("Error creating TUN interface: %v", err)
	}
	defer tun.Close()

	if err := configureTun(ifName, "10.0.0.2/24", 1400); err != nil {
		log.Fatalf("Error configuring TUN interface: %v", err)
	}

	conn, serverAddr, err := createClientSocket(serverAddrStr)
	if err != nil {
		log.Fatalf("Error connecting to server: %v", err)
	}
	defer conn.Close()

	bypassRoute, err := setupClientRoutes(ifName, serverAddr.IP)
	if err != nil {
		log.Fatalf("Error configuring client routes: %v", err)
	}

	var cleanupOnce sync.Once
	cleanupRoute := func() {
		cleanupOnce.Do(func() {
			if bypassRoute != nil {
				if err := netlink.RouteDel(bypassRoute); err != nil {
					log.Printf("Error deleting bypass route: %v", err)
				}
			}
		})
	}
	defer cleanupRoute()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cleanupRoute()
		os.Exit(0)
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// ==========================================
	// GOROUTINE 1: OUTBOUND (TUN -> UDP Server)
	// ==========================================
	go func() {
		defer wg.Done()
		buffer := make([]byte, 2048)

		for {
			n, err := tun.Read(buffer)
			if err != nil {
				log.Printf("TUN Read Error: %v", err)
				continue
			}

			rawPacket := buffer[:n]

			encryptedPayload, err := encrypt(rawPacket, key)
			if err != nil {
				log.Printf("Encrypt Error: %v", err)
				continue
			}

			if _, err := conn.Write(encryptedPayload); err != nil {
				log.Printf("UDP Write Error: %v", err)
			}
		}
	}()

	// ==========================================
	// GOROUTINE 2: INBOUND (UDP Server -> TUN)
	// ==========================================
	go func() {
		defer wg.Done()
		buffer := make([]byte, 2048)

		for {
			n, err := conn.Read(buffer)
			if err != nil {
				log.Printf("UDP Read Error: %v", err)
				continue
			}

			payload := buffer[:n]

			rawPacket, err := decrypt(payload, key)
			if err != nil {
				log.Printf("Decrypt Error: %v", err)
				continue
			}

			if _, err := tun.Write(rawPacket); err != nil {
				log.Printf("TUN Write Error: %v", err)
			}
		}
	}()

	wg.Wait()
}
