// SPDX-FileCopyrightText: 2025 Elektronikutvecklingsbyrån EUB AB <https://eub.se>
// SPDX-License-Identifier: MIT

package main

import (
	"flag"
	"fmt"
	"net"
	"log"
	"sync"
	"os"
	"os/exec"
	"encoding/csv"
	"encoding/hex"
	"io"
	"strings"
	"context"
	"time"

	"github.com/pion/dtls/v3"
)

func chanFromConn(conn net.Conn, id string) chan []byte {
    c := make(chan []byte)

    go func() {
        b := make([]byte, 2048)

        for {
            n, err := conn.Read(b)
            if n > 0 {
                res := make([]byte, n)
                copy(res, b[:n])
                c <- res
            }
            if err != nil {
				log.Printf("[%s] conn read error: %v", id, err)
                c <- nil
                break
            }
        }
    }()

    return c
}

// --- Simple pipe function ---
func pipe(conn1 net.Conn, conn2 net.Conn, id string) {
	defer conn1.Close() // <- make sure both get closed
    defer conn2.Close()

    chan1 := chanFromConn(conn1, id)
    chan2 := chanFromConn(conn2, id)

    for {
        select {
        case b1 := <-chan1:
            if b1 == nil {
				log.Printf("[%s] Broken pipe? (conn1)", id)
                return
            } else {
				if _, err := conn2.Write(b1); err != nil {
					log.Printf("write error conn2: %v", err)
					return
				}
			}
		case b2 := <-chan2:
			if b2 == nil {
				log.Printf("[%s] Broken pipe? (conn1)", id)
				return
			} else {
				if _, err := conn1.Write(b2); err != nil {
					log.Printf("[%s] write error conn1: %v", id, err)
					return
				}
			}
		}
	}
}

// -- Session cleanup stuff --
var (
    mu       sync.Mutex
    sessions = make(map[string]*dtls.Conn) // keyed by PSK identity
)

func registerSession(pskID string, c *dtls.Conn) {
    mu.Lock()
    defer mu.Unlock()

    if old, ok := sessions[pskID]; ok {
		log.Printf("[%s] closing old session, replacing with new one", pskID)
        old.Close()          // tear down old one
        delete(sessions, pskID)
    }

    sessions[pskID] = c
    log.Printf("[%s] registered new session", pskID)
}

func unregisterSession(pskID string, c *dtls.Conn) {
    mu.Lock()
    defer mu.Unlock()

    if current, ok := sessions[pskID]; ok && current == c {
        current.Close()
        delete(sessions, pskID)
        log.Printf("[%s] session unregistered", pskID)
    }
}

// -- cmd line args --
var (
    bindAddr    = flag.String("bind", ":4444", "UDP listen address")
    connectAddr = flag.String("connect", "127.0.0.1:9999", "Upstream UDP address")
    pskCSV      = flag.String("psk-csv", "", "Path to CSV file with PSK identities and keys")
    shellKMS    = flag.String("shell-kms-cmd", "", "Shell command to run for PSK lookup")
	requireEMS  = flag.Bool("require-ems", false, "Only allow connections with Extended Master Secret (RFC 7627)")
)

var pskMap = map[string][]byte{}

func loadPSKCSV(path string) error {
    f, err := os.Open(path)
    if err != nil {
        return err
    }
    defer f.Close()

    r := csv.NewReader(f)
    for {
        rec, err := r.Read()
        if err == io.EOF {
            break
        }
        if err != nil {
            return err
        }
        if len(rec) < 2 {
            continue
        }
        id, hexKey := rec[0], rec[1]
        key, err := hex.DecodeString(hexKey)
        if err != nil {
            return fmt.Errorf("invalid hex for id %s: %w", id, err)
        }
        pskMap[id] = key
    }
    return nil
}

func lookupKey(id string) ([]byte, error) {
    if key, ok := pskMap[id]; ok {
		log.Printf("key found for %s", id)
        return key, nil
    }
    if *shellKMS != "" {
		// require shellKMS to be a single executable path (no shell interpolation)
		cmdPath, err := exec.LookPath(*shellKMS)
		if err != nil {
			return nil, fmt.Errorf("kms helper not found: %w", err)
		}

		cmd := exec.Command(cmdPath, id)
		out, err := cmd.Output()
        if err != nil {
			log.Printf("shell exec error: %v", err)
            return nil, err
        }
        key, err := hex.DecodeString(strings.TrimSpace(string(out)))
        if err != nil {
			log.Printf("hex decode error: %v", err)
            return nil, err
        }
		log.Printf("key %v found for %s", key, id)
        return key, nil
    }
    return nil, fmt.Errorf("unknown PSK id %s", id)
}

func main() {

	flag.Parse()

	if *pskCSV != "" {
		if err := loadPSKCSV(*pskCSV); err != nil {
			log.Fatalf("failed to load PSK CSV: %v", err)
		}
	}

	config := &dtls.Config{
		PSK: func(identityHint []byte) ([]byte, error) {
			id := string(identityHint)
			return lookupKey(id)
		},
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_PSK_WITH_AES_128_CCM,
			dtls.TLS_PSK_WITH_AES_128_CCM_8,
			dtls.TLS_PSK_WITH_AES_256_CCM_8,
			dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
		},
		ExtendedMasterSecret: func() dtls.ExtendedMasterSecretType {
			if *requireEMS {
				return dtls.RequireExtendedMasterSecret
			}
			return dtls.RequestExtendedMasterSecret
		}(),
		ConnectionIDGenerator: dtls.RandomCIDGenerator(8),
	}

	upstreamAddr := *connectAddr

	// start dtls server
	addr, err := net.ResolveUDPAddr("udp", *bindAddr)
	listener, err := dtls.Listen("udp", addr, config)
	if err != nil { panic(err) }

	defer func() {
		listener.Close()
	}()

	fmt.Println("Listening")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}

		dtlsConn := conn.(*dtls.Conn)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := dtlsConn.HandshakeContext(ctx); err != nil {
			cancel()
			log.Printf("handshake failed: %v", err)
			dtlsConn.Close()
			continue
		}
		cancel()

		if state, ok := dtlsConn.ConnectionState(); ok {
			pskID := string(state.IdentityHint)
			registerSession(pskID, dtlsConn)

			go func(c *dtls.Conn, id string) {
				defer unregisterSession(id, c)
				upstream, err := net.Dial("udp", upstreamAddr)
				if err != nil {
					log.Printf("[%s] upstream dial error: %v", id, err)
					c.Close()
					return
				}
				pipe(c, upstream, pskID)
			}(dtlsConn, pskID)

		} else {
			log.Printf("connection state not ready")
			dtlsConn.Close()
		}
	}


}
