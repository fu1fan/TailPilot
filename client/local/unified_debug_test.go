// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package local

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestDebugActionJSON(t *testing.T) {
	for _, status := range []int{200, 403, 409} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer server.Close()
				req, err := http.ReadRequest(bufio.NewReader(server))
				if err != nil {
					t.Error(err)
					return
				}
				data, _ := io.ReadAll(req.Body)
				req.Body.Close()
				if req.Method != "POST" || req.URL.Path != "/localapi/v0/debug" || req.URL.Query().Get("action") != "unified-policy-preview" || !strings.Contains(string(data), `"file":"/policy.json"`) {
					t.Errorf("bad request %v %s", req.URL, data)
				}
				body := `{"schemaValid":true}`
				fmt.Fprintf(server, "HTTP/1.1 %d status\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, len(body), body)
			}()
			lc := &Client{Dial: func(context.Context, string, string) (net.Conn, error) { return client, nil }}
			got, err := lc.DebugActionJSON(context.Background(), "unified-policy-preview", map[string]string{"file": "/policy.json"})
			if (err == nil) != (status == 200) {
				t.Fatalf("%s %v", got, err)
			}
			<-done
		})
	}
}
