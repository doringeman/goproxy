package goproxy_test

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/require"
)

func TestMitmSendsContinueBeforeReadingBody(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		name := "cleartext"
		if useTLS {
			name = "TLS"
		}
		t.Run(name, func(t *testing.T) {
			body := strings.Repeat("x", 80_000)
			received := make(chan string, 1)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				data, err := io.ReadAll(r.Body)
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				received <- string(data)
				w.WriteHeader(http.StatusCreated)
			})

			upstream := httptest.NewUnstartedServer(handler)
			if useTLS {
				upstream.StartTLS()
			} else {
				upstream.Start()
			}
			defer upstream.Close()
			upstreamURL, err := url.Parse(upstream.URL)
			require.NoError(t, err)

			proxy := goproxy.NewProxyHttpServer()
			proxy.Tr.TLSClientConfig = &tls.Config{
				InsecureSkipVerify: true,
			}
			proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
			proxy.OnRequest().DoFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Request, *http.Response) {
				if req.URL.Path == "/reject" {
					return nil, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "blocked")
				}
				return req, nil
			})
			proxyServer := httptest.NewServer(proxy)
			defer proxyServer.Close()

			raw, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", proxyServer.Listener.Addr().String())
			require.NoError(t, err)
			defer raw.Close()
			require.NoError(t, raw.SetDeadline(time.Now().Add(3*time.Second)))
			_, err = fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamURL.Host, upstreamURL.Host)
			require.NoError(t, err)
			connectResponse, err := http.ReadResponse(bufio.NewReader(raw), nil)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, connectResponse.StatusCode)
			require.NoError(t, connectResponse.Body.Close())

			var conn net.Conn
			if useTLS {
				tlsConn := tls.Client(raw, &tls.Config{
					InsecureSkipVerify: true,
				})
				require.NoError(t, tlsConn.HandshakeContext(t.Context()))
				conn = tlsConn
			} else {
				conn = raw
			}
			_, err = fmt.Fprintf(conn,
				"PUT /upload HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nExpect: 100-continue\r\n\r\n",
				upstreamURL.Host, len(body))
			require.NoError(t, err)
			reader := bufio.NewReader(conn)
			interim, err := http.ReadResponse(reader, nil)
			require.NoError(t, err)
			require.Equal(t, http.StatusContinue, interim.StatusCode)
			require.NoError(t, interim.Body.Close())

			_, err = io.WriteString(conn, body)
			require.NoError(t, err)
			final, err := http.ReadResponse(reader, nil)
			require.NoError(t, err)
			require.Equal(t, http.StatusCreated, final.StatusCode)
			require.NoError(t, final.Body.Close())
			require.Equal(t, body, <-received)

			_, err = fmt.Fprintf(conn,
				"PUT /reject HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nExpect: 100-continue\r\n\r\n",
				upstreamURL.Host, len(body))
			require.NoError(t, err)
			rejected, err := http.ReadResponse(reader, nil)
			require.NoError(t, err)
			require.Equal(t, http.StatusForbidden, rejected.StatusCode)
			require.NoError(t, rejected.Body.Close())
		})
	}
}
