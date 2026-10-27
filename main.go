package main

import (
	"bufio"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/unix"
)

func createTun(name string) (*os.File, string, error) {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open /dev/net/tun: %w", err)
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		file.Close()
		return nil, "", fmt.Errorf("failed to create ifreq: %w", err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)

	if err := unix.IoctlIfreq(int(file.Fd()), unix.TUNSETIFF, ifr); err != nil {
		file.Close()
		return nil, "", fmt.Errorf("TUNSETIFF failed: %w", err)
	}

	return file, ifr.Name(), nil
}

func configureTun(name string, cidr string, mtu int) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", name, err)
	}

	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %s: %w", cidr, err)
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add address to %s: %w", name, err)
	}

	if mtu > 0 {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return fmt.Errorf("failed to set MTU on %s: %w", name, err)
		}
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up %s: %w", name, err)
	}

	return nil
}

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Layout: [Nonce (24)] + [Ciphertext] + [MAC (16)]
	encrypted := aead.Seal(nonce, nonce, plaintext, nil)
	return encrypted, nil
}

func decrypt(encrypted []byte, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()

	if len(encrypted) < nonceSize+aead.Overhead() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func loadEnv(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 && os.Getenv(parts[0]) == "" {
			os.Setenv(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
}

func main() {
	loadEnv(".env")

	mode := flag.String("mode", "", "Mode to run: 'server' or 'client'")
	serverAddr := flag.String("server", "127.0.0.1:7646", "Server address (host:port) when running in client mode")
	flag.Parse()

	switch *mode {
	case "server":
		log.Println("Starting VPN in server mode...")
		runServer()
	case "client":
		log.Printf("Starting VPN in client mode (connecting to %s)...", *serverAddr)
		runClient(*serverAddr)
	default:
		log.Fatalf("Usage: sudo ./vpn -mode=[server|client] [-server=host:port]")
	}
}
