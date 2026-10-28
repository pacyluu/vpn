package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"

	"github.com/vishvananda/netlink"
)

func setupServerNAT() error {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644); err != nil {
		return fmt.Errorf("failed to enable ip_forward: %w", err)
	}

	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("failed to list routes: %w", err)
	}

	var outIfName string
	for _, r := range routes {
		if r.Dst == nil || r.Dst.IP.Equal(net.IPv4zero) {
			link, err := netlink.LinkByIndex(r.LinkIndex)
			if err == nil {
				outIfName = link.Attrs().Name
				break
			}
		}
	}

	if outIfName == "" {
		return fmt.Errorf("could not determine default outbound interface")
	}

	checkCmd := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "10.0.0.0/24", "-o", outIfName, "-j", "MASQUERADE")
	if err := checkCmd.Run(); err != nil {
		addCmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.0.0.0/24", "-o", outIfName, "-j", "MASQUERADE")
		if out, err := addCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("iptables MASQUERADE failed: %v (%s)", err, string(out))
		}
	}

	return nil
}

func createServerSocket(addr_str string) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", addr_str)
	if err != nil {
		log.Fatalf("Failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("Failed to start UDP listener: %v", err)
	}

	return conn, err
}

func runServer() {
	tun, ifName, err := createTun("tun0")
	if err != nil {
		log.Fatalf("Error creating TUN interface: %v", err)
	}
	defer tun.Close()

	if err := configureTun(ifName, "10.0.0.1/24", 1400); err != nil {
		log.Fatalf("Error configuring TUN interface: %v", err)
	}

	if err := setupServerNAT(); err != nil {
		log.Fatalf("Error configuring server NAT: %v", err)
	}

	conn, err := createServerSocket(":7646")
	if err != nil {
		log.Fatalf("Error creating socket: %s", err)
	}
	defer conn.Close()

	keyStr := os.Getenv("KEY")
	key, err := hex.DecodeString(keyStr)
	if err != nil || len(key) != 32 {
		log.Fatalf("Invalid KEY (expected 64-char hex string for 32-byte AES-256 key): %v", err)
	}

	var clientAddr *net.UDPAddr
	var addrMutex sync.RWMutex

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buffer := make([]byte, 2048)

		for {
			n, addr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				log.Printf("UDP Read Error: %v", err)
				continue
			}

			addrMutex.Lock()
			clientAddr = addr
			addrMutex.Unlock()

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

	//OUTBOUND (TUN -> UDP)
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

			addrMutex.RLock()
			target := clientAddr
			addrMutex.RUnlock()

			if target != nil {
				if _, err := conn.WriteToUDP(encryptedPayload, target); err != nil {
					log.Printf("UDP Write Error: %v", err)
				}
			}
		}
	}()

	wg.Wait()

}
