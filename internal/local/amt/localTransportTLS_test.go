/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package amt

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/apf"
	"github.com/device-management-toolkit/rpc-go/v2/internal/lm"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/pthi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// localTransportCloser is satisfied by both transports; assert it at compile time.
var (
	_ localTransportCloser = (*LocalTransport)(nil)
	_ localTransportCloser = (*LocalTLSTransport)(nil)
)

// pipeHECI is an in-memory heci.Interface bridged to a fake AMT device.
type pipeHECI struct {
	rx     chan []byte
	tx     chan []byte
	closed chan struct{}
	once   sync.Once
}

func newPipeHECI() *pipeHECI {
	return &pipeHECI{
		rx:     make(chan []byte, 64),
		tx:     make(chan []byte, 64),
		closed: make(chan struct{}),
	}
}

func (p *pipeHECI) Init(useLME, useWD bool) error { return nil }
func (p *pipeHECI) InitWithGUID(guid any) error   { return nil }
func (p *pipeHECI) InitHOTHAM() error             { return nil }
func (p *pipeHECI) GetBufferSize() uint32         { return 5120 }

func (p *pipeHECI) SendMessage(buffer []byte, done *uint32) (int, error) {
	frame := append([]byte(nil), buffer...)

	select {
	case p.tx <- frame:
	case <-p.closed:
	}

	return len(buffer), nil
}

func (p *pipeHECI) ReceiveMessage(buffer []byte, done *uint32) (int, error) {
	select {
	case frame, ok := <-p.rx:
		if !ok {
			return 0, nil
		}

		return copy(buffer, frame), nil
	case <-p.closed:
		return 0, nil
	}
}

func (p *pipeHECI) Close() { p.once.Do(func() { close(p.closed) }) }

func (p *pipeHECI) feed(b []byte) {
	select {
	case p.rx <- b:
	case <-p.closed:
	}
}

// startTLSDevice bridges APF frames on p to a tls.Server that runs serve.
func startTLSDevice(t *testing.T, p *pipeHECI, amtCh uint32, serve func(net.Conn)) {
	t.Helper()

	devSide, srvSide := net.Pipe()

	go func() {
		for {
			select {
			case frame := <-p.tx:
				switch frame[0] {
				case apf.APF_CHANNEL_OPEN:
					var om apf.APF_CHANNEL_OPEN_MESSAGE

					_ = binary.Read(bytes.NewReader(frame), binary.BigEndian, &om)

					conf := apf.APF_CHANNEL_OPEN_CONFIRMATION_MESSAGE{
						MessageType:       apf.APF_CHANNEL_OPEN_CONFIRMATION,
						RecipientChannel:  om.SenderChannel,
						SenderChannel:     amtCh,
						InitialWindowSize: apf.LME_RX_WINDOW_SIZE,
						Reserved:          0xFFFFFFFF,
					}

					var b bytes.Buffer

					_ = binary.Write(&b, binary.BigEndian, conf)
					p.feed(b.Bytes())
				case apf.APF_CHANNEL_DATA:
					length := binary.BigEndian.Uint32(frame[5:9])

					if _, err := devSide.Write(frame[9 : 9+int(length)]); err != nil {
						return
					}

					p.feed(apf.BuildChannelWindowAdjustBytes(amtCh, length))
				case apf.APF_CHANNEL_CLOSE:
					_ = devSide.Close()

					return
				}
			case <-p.closed:
				_ = devSide.Close()

				return
			}
		}
	}()

	go func() {
		buf := make([]byte, 4096)

		for {
			n, err := devSide.Read(buf)
			if n > 0 {
				p.feed(apf.BuildChannelDataBytes(amtCh, append([]byte(nil), buf[:n]...)))
			}

			if err != nil {
				// Mirror AMT closing the channel after a Connection: close response so
				// the client's read pump exits promptly.
				p.feed(apf.BuildChannelCloseBytes(amtCh))

				return
			}
		}
	}()

	go serve(srvSide)
}

func selfSignedCert(t *testing.T) cryptotls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	return cryptotls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestLocalTLSTransport_RoundTrip exercises the full bespoke request path:
// serialize → TLS handshake over APF → write → ReadResponse → buffer body →
// finishChannel, against a fake HECI bridged to a TLS HTTP server.
func TestLocalTLSTransport_RoundTrip(t *testing.T) {
	srvCfg := &cryptotls.Config{Certificates: []cryptotls.Certificate{selfSignedCert(t)}}

	p := newPipeHECI()
	defer p.Close()

	startTLSDevice(t, p, 9, func(raw net.Conn) {
		srv := cryptotls.Server(raw, srvCfg)
		if err := srv.HandshakeContext(context.Background()); err != nil {
			return
		}

		if _, err := http.ReadRequest(bufio.NewReader(srv)); err != nil {
			return
		}

		_, _ = io.WriteString(srv, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
		_ = srv.Close()
	})

	restore := lmeInitializer
	lmeInitializer = func() (*lm.LMEConnection, error) {
		return &lm.LMEConnection{Command: pthi.Command{Heci: p}}, nil
	}

	defer func() { lmeInitializer = restore }()

	transport := NewLocalTLSTransport(&cryptotls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed AMT cert in test
	defer transport.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://localhost:16993/wsman", bytes.NewReader([]byte("<wsman/>")))
	require.NoError(t, err)

	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "OK", string(body))
}

// TestLocalTLSTransport_InitErrorSurfaced verifies an LME init failure is
// reported on the request rather than panicking.
func TestLocalTLSTransport_InitErrorSurfaced(t *testing.T) {
	restore := lmeInitializer
	lmeInitializer = func() (*lm.LMEConnection, error) {
		return nil, assert.AnError
	}

	defer func() { lmeInitializer = restore }()

	transport := NewLocalTLSTransport(&cryptotls.Config{InsecureSkipVerify: true}) //nolint:gosec // test
	defer transport.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://localhost:16993/wsman", nil)
	require.NoError(t, err)

	resp, err := transport.RoundTrip(req)
	require.Error(t, err)

	if resp != nil {
		_ = resp.Body.Close()
	}
}
