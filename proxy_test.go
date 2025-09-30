package main

import (
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	// "github.com/pion/dtls/v3/pkg/protocol/extension"
	// "github.com/pion/dtls/v3/pkg/protocol/handshake"
)

var serverAddr = "127.0.0.1:5683" // must match --bind
var pskID = []byte("Kalle")
var pskKey = []byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef} // must match CSV/KMS entry


// TestProxyHandshake verifies that a DTLS handshake with the proxy succeeds.
// It assumes the proxy is already running in the background.
func TestProxyHandshake(t *testing.T) {

	config := &dtls.Config{
		PSK: func(hint []byte) ([]byte, error) {
			return pskKey, nil
		},
		PSKIdentityHint: pskID,
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
			dtls.TLS_PSK_WITH_AES_128_CCM,
			dtls.TLS_PSK_WITH_AES_128_CCM_8,
			dtls.TLS_PSK_WITH_AES_256_CCM_8,
		},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	}

	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Fatalf("resolve udp: %v", err)
	}

	udpConn, err := net.ListenUDP("udp", nil) // unconnected
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udpConn.Close()

	dtlsConn, err := dtls.Client(udpConn, udpAddr, config)
	if err != nil {
		t.Fatalf("dtls handshake failed: %v", err)
	}
	defer dtlsConn.Close()

	// Try a write
	msg := []byte("hello proxy")
	dtlsConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := dtlsConn.Write(msg); err != nil {
		t.Fatalf("dtls write failed: %v", err)
	}

	buf := make([]byte, 1500)
	deadline := time.Now().Add(1 * time.Second)
	dtlsConn.SetReadDeadline(deadline)

	n, err := dtlsConn.Read(buf)
	if n > 0 {
		t.Logf("got %d bytes back: %x", n, buf[:n])
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		// timeout as expected
		return
	}
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
}

// newDTLSClient creates a DTLS client on top of a UDP PacketConn.
// Takes an existing UDP PacketConn, the remote Addr, and a dtls.Config.
// Returns a connected *dtls.Conn or error.
func newDTLSClient(udpConn net.PacketConn, rAddr net.Addr, cfg *dtls.Config) (*dtls.Conn, error) {
    c, err := dtls.Client(udpConn, rAddr, cfg)
    if err != nil {
        return nil, err
    }
    return c, nil
}

func TestEcho(t *testing.T) {
	serverAddr := "127.0.0.1:5683"
	pskID := []byte("Kalle")
	pskKey, _ := hex.DecodeString("deadbeefdeadbeef")

	cfg := &dtls.Config{
		PSKIdentityHint: pskID,
		PSK: func(_ []byte) ([]byte, error) {
			return pskKey, nil
		},
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
			dtls.TLS_PSK_WITH_AES_128_CCM,
			dtls.TLS_PSK_WITH_AES_128_CCM_8,
			dtls.TLS_PSK_WITH_AES_256_CCM_8,
		},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	}

	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Fatal(err)
	}

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	c, err := dtls.Client(udpConn, udpAddr, cfg)
	if err != nil {
		t.Fatalf("dtls handshake failed: %v", err)
	}
	defer c.Close()

	msg := []byte("ping")
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	buf := make([]byte, 1500)
	c.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	got := string(buf[:n])
	if got != string(msg) {
		t.Fatalf("expected echo %q, got %q", msg, got)
	}
}


func TestSessionReplacement(t *testing.T) {
	serverAddr := "127.0.0.1:5683"
	pskID := []byte("Kalle")
	pskKey, _ := hex.DecodeString("deadbeefdeadbeef")

	cfg := &dtls.Config{
		PSKIdentityHint: pskID,
		PSK: func(_ []byte) ([]byte, error) {
			return pskKey, nil
		},
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
			dtls.TLS_PSK_WITH_AES_128_CCM,
			dtls.TLS_PSK_WITH_AES_128_CCM_8,
			dtls.TLS_PSK_WITH_AES_256_CCM_8,
		},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	}

	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Fatal(err)
	}

	// --- Client #1 ---
	c1udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c1udp.Close()

	c1, err := dtls.Client(c1udp, udpAddr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()

	msg1 := []byte("hello from client1")
	if _, err := c1.Write(msg1); err != nil {
		t.Fatalf("c1 write: %v", err)
	}
	buf := make([]byte, 1500)
	n, err := c1.Read(buf)
	if err != nil {
		t.Fatalf("c1 read: %v", err)
	}
	if got := string(buf[:n]); got != string(msg1) {
		t.Fatalf("c1 expected %q, got %q", msg1, got)
	}

	// --- Client #2 with same PSK ID ---
	c2udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c2udp.Close()

	c2, err := dtls.Client(c2udp, udpAddr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	msg2 := []byte("hello from client2")
	if _, err := c2.Write(msg2); err != nil {
		t.Fatalf("c2 write: %v", err)
	}
	n, err = c2.Read(buf)
	if err != nil {
		t.Fatalf("c2 read: %v", err)
	}
	if got := string(buf[:n]); got != string(msg2) {
		t.Fatalf("c2 expected %q, got %q", msg2, got)
	}

	// --- Verify client #1 lost connection (write should fail) ---
	c1.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := c1.Write([]byte("still here?")); err == nil {
		t.Fatal("expected c1 to fail writing after being replaced, but write succeeded")
	} else {
		t.Logf("c1 write failed as expected after replacement: %v", err)
	}
}

func TestBadPSKDoesNotBlockGoodClient(t *testing.T) {
	serverAddr := "127.0.0.1:5683"
	pskID := []byte("Kalle")
	goodKey, _ := hex.DecodeString("deadbeefdeadbeef")
	badKey, _ := hex.DecodeString("ffffffffffffffff")

	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Fatal(err)
	}

	// --- Client #1: bad PSK (handshake will hang) ---
	badUDP, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer badUDP.Close()

	badCfg := &dtls.Config{
		PSKIdentityHint: pskID,
		PSK: func(_ []byte) ([]byte, error) { return badKey, nil },
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
			dtls.TLS_PSK_WITH_AES_128_CCM,
			dtls.TLS_PSK_WITH_AES_128_CCM_8,
			dtls.TLS_PSK_WITH_AES_256_CCM_8,
		},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	}

	go func() {
		// This will hang, that's expected
		_, _ = dtls.Client(badUDP, udpAddr, badCfg)
	}()

	// --- Client #2: good PSK (should still succeed) ---
	goodUDP, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer goodUDP.Close()

	goodCfg := &dtls.Config{
		PSKIdentityHint: pskID,
		PSK: func(_ []byte) ([]byte, error) { return goodKey, nil },
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
			dtls.TLS_PSK_WITH_AES_128_CCM,
			dtls.TLS_PSK_WITH_AES_128_CCM_8,
			dtls.TLS_PSK_WITH_AES_256_CCM_8,
		},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	}

	goodConn, err := dtls.Client(goodUDP, udpAddr, goodCfg)
	if err != nil {
		t.Fatalf("good client handshake failed: %v", err)
	}
	defer goodConn.Close()

	msg := []byte("hello-good")
	if _, err := goodConn.Write(msg); err != nil {
		t.Fatalf("good client write failed: %v", err)
	}

	buf := make([]byte, 1500)
	goodConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := goodConn.Read(buf)
	if err != nil {
		t.Fatalf("good client read failed: %v", err)
	}

	if got := string(buf[:n]); got != string(msg) {
		t.Fatalf("good client expected echo %q, got %q", msg, got)
	}
}
