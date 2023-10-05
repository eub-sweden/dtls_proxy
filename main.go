// SPDX-FileCopyrightText: 2023 Elektronikutvecklingsbyrån EUB AB <https://www.eub.se/en>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"net"
	"time"
	"flag"
	"log"
	"os"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/examples/util"
)

func chanFromConn(conn net.Conn) chan []byte {
    c := make(chan []byte)

    go func() {
        b := make([]byte, 1024)

        for {
            n, err := conn.Read(b)
            if n > 0 {
                res := make([]byte, n)
                copy(res, b[:n])
                c <- res
            }
            if err != nil {
                c <- nil
                break
            }
        }
    }()

    return c
}

func pipe(conn1 net.Conn, conn2 net.Conn) {
    chan1 := chanFromConn(conn1)
    chan2 := chanFromConn(conn2)

    for {
        select {
        case b1 := <-chan1:
            if b1 == nil {
				fmt.Println("Broken pipe?")
                return
            } else {
                conn2.Write(b1)
            }
        case b2 := <-chan2:
            if b2 == nil {
				fmt.Println("Broken pipe?")
                return
            } else {
                conn1.Write(b2)
            }
        }
    }
}

func pskLookup(pskId []byte, kms map[string][]byte) []byte {
	psk := kms[string(pskId)]
	if psk == nil {
		fmt.Printf("Client \"%s\" not found!\n", pskId)
	} else {
		fmt.Printf("Client \"%s\" found\n", pskId)
	}

	return psk
}

func mapFromCsv(path string) map[string][]byte {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	csvReader := csv.NewReader(f)
	data, err := csvReader.ReadAll()
	if err != nil {
		log.Fatal(err)
	}

	var m map[string][]byte
	m = make(map[string][]byte)

	for _, e := range data {
		psk, err := hex.DecodeString(e[1])
		if err != nil {
			log.Fatal(err)
		}

		m[e[0]] = psk
	}

	return m
}



func pskIdFromConn(conn net.Conn) string {
	var dtlsConn *dtls.Conn = conn.(*dtls.Conn)
	hint := string(dtlsConn.ConnectionState().IdentityHint)

	return hint
}

func main() {
	bindPtr := flag.String("bind", "0.0.0.0:14881", "local ip:port to bind");
	upsPtr := flag.String("connect", "kontor.eub.se:14999", "upstream plaintext ip:port")
	csvPtr := flag.String("psk-csv", "keys.csv", "id/psk csv file")

	flag.Parse()

	fmt.Println("bind:", *bindPtr);
	fmt.Println("ups:", *upsPtr);
	fmt.Println("csv:", *csvPtr);

	// Map between conns and PSK IDs, used to terminate stale connections
	var connMap map[string]net.Conn
	connMap = make(map[string]net.Conn)

	kms := mapFromCsv(*csvPtr)

	upstreamAddr := *upsPtr;

	addr, err := net.ResolveUDPAddr("udp", *bindPtr);
	util.Check(err);

	// Create parent context to cleanup handshaking connections on exit.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		// Create timeout context for accepted connection.
		ConnectContextMaker: func() (context.Context, func()) {
			return context.WithTimeout(ctx, 30*time.Second)
		},
        ConnectionIDGenerator: dtls.RandomCIDGenerator(8),
		PSK: func(hint []byte) ([]byte, error) {
			return pskLookup(hint, kms), nil
		},
		CipherSuites: []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_CCM_8},
	}

	listener, err := dtls.Listen("udp", addr, config)
	util.Check(err)
	defer func() {
		util.Check(listener.Close())
	}()

	for {
		// Wait for a connection.
		fmt.Println("Listening")

		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		// Chect if there's an existing connection that has gone stale
		pskId := pskIdFromConn(conn)
		staleConn := connMap[pskId]
		if staleConn != nil {
			fmt.Println("Closing stale connection from ", pskId)
			staleConn.Close()
		}
		connMap[pskIdFromConn(conn)] = conn

		other_conn, err := net.Dial("udp", upstreamAddr);
		if err != nil {
			log.Fatal("net.Dial failed:", err)
			continue;
		}

		go pipe(conn, other_conn);
	}
}
