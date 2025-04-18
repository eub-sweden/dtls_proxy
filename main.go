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
	"net/http"
	"strings"
	"io"
	"os/exec"

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

func pskMapLookup(pskId []byte, kms map[string][]byte) []byte {
	psk := kms[string(pskId)]
	if psk == nil {
		fmt.Printf("Client \"%s\" not found!\n", pskId)
	} else {
		fmt.Printf("Client \"%s\" found\n", pskId)
	}

	return psk
}

var extraRestHeaders = make(map[string]string)
var idQueryKey string
var idQueryVal string

func pskRestLookup(pskId []byte, url string, extraQ string) []byte {
	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Print(err)
		return nil
	}

	q := req.URL.Query()

	// FIXME: We should construct a single global request with everything except
	// the query populated, since that's the only thing that changes between
	// requests
	q.Add(idQueryKey, idQueryVal + string(pskId))
	if len(extraQ) > 0 {
		splitExtraQ := strings.Split(extraQ, "=")
		q.Add(splitExtraQ[0], splitExtraQ[1])
	}

	req.URL.RawQuery = q.Encode()

	// Iterate over all extra headers
	for k, v := range extraRestHeaders {
		req.Header.Add(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Print(err)
		return nil
	}

	resBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Print(err)
		return nil
	}

	// FIXME: now convert from ascii hex to bytes
	rawbytes, err := hex.DecodeString(string(resBody))
	if err != nil {
		log.Print(err)
		return nil
	}

	fmt.Println("http response: ", resBody)
	fmt.Println("decoded http response: ", rawbytes)

	return rawbytes
}

var shellKmsCmd string

// Executes shell process "shellKmsCmd $pskId" and returns its stdout
func pskShellLookup(pskId []byte) []byte {

	cmd := exec.Command(shellKmsCmd, string(pskId))
	stdout, err := cmd.Output()
	if err != nil {
		log.Print(err)
		return nil
	}

	fmt.Println("stdout: ", string(stdout))

	// FIXME: TODO: As a courtesy, strip terminating line (but only if the
	// number of chars returned is odd?)
	rawbytes, err := hex.DecodeString(string(stdout))
	if err != nil {
		log.Print(err)
		return nil
	}

	return rawbytes
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
	csvPtr := flag.String("psk-csv", "", "id/psk csv file")
	restPtr := flag.String("psk-rest", "", "id/psk rest looup uri")
	restHdrsPtr := flag.String("rest-headers", "", "extra headers for REST kms")
	idQueryKeyPtr := flag.String("id-query-key", "", "query key used for REST kms")
	idQueryValPtr := flag.String("id-query-val-prefix", "", "query value prefix used for REST kms")
	shellKmsPtr := flag.String("shell-kms-cmd", "", "Use shell cmd kms")

	flag.Parse()

	fmt.Println("bind:", *bindPtr);
	fmt.Println("ups:", *upsPtr);

	// Map between conns and PSK IDs, used to terminate stale connections
	var connMap map[string]net.Conn
	connMap = make(map[string]net.Conn)

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
		CipherSuites: []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_CCM_8},
	}

	if len(*restHdrsPtr) > 0 {

		keyval := strings.Split(*restHdrsPtr, ":")
		extraRestHeaders[keyval[0]] = keyval[1]

		for k, v := range extraRestHeaders {
			fmt.Println("extra headers: ", k, ": ", v)
		}
	}

	if len(*idQueryKeyPtr) > 0 {
		idQueryKey = *idQueryKeyPtr
	} else {
		idQueryKey = "pskId"
	}

	if len(*idQueryValPtr) > 0 {
		idQueryVal = *idQueryValPtr
	} else {
		idQueryVal = ""
	}

	// If KMS lookup is via local csv, create a map from it
	if len(*csvPtr) > 0 {
		fmt.Println("csv:", *csvPtr);
		kmsMap := mapFromCsv(*csvPtr);
		config.PSK = func(hint []byte) ([]byte, error) {
			return pskMapLookup(hint, kmsMap), nil
		};

	} else if len(*restPtr) > 0 {
		fmt.Println("Targeting kms url:", *restPtr);

		// Split into base and query param
		var base string;
		var xtra string;
		split := strings.Split(*restPtr, "?")
		if len(split) == 2 {
			base = split[0];
			xtra = split[1]
			fmt.Println("url: ", base, " and ", xtra);
		} else {
			base = *restPtr;
			xtra = "";
		}

		config.PSK = func(hint []byte) ([]byte, error) {
			return pskRestLookup(hint, base, xtra), nil
		};

	} else if len(*shellKmsPtr) > 0 {
		shellKmsCmd = *shellKmsPtr
		config.PSK = func(hint []byte) ([]byte, error) {
			return pskShellLookup(hint), nil
		};

	} else {
		fmt.Println("No KMS lookup method provided!");
		os.Exit(1)
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

		// DTLS sessions with ConnectionId can potentially last for days without
		// any activity. For this reason we can't rely on the stack or the OS to
		// garbage collect stale connections. The only indicator we have that a
		// connection has gone stale is the client reconnecting with the same
		// PskId. When this occurs, we close the old connection to prevent
		// memory leaks.
		// FIXME: Optimally, we would cull these after X time of inactivity, or
		// simply Y time since handshake so that the session keys never get too
		// old
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
