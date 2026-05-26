/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package lm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
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
	"github.com/device-management-toolkit/rpc-go/v2/pkg/pthi"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pipeHECI is an in-memory heci.Interface: rx carries frames into APFConn (read
// by ReceiveMessage) and tx captures frames APFConn sends. A fake AMT device
// goroutine drains tx and feeds rx to drive the channel lifecycle.
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

func (p *pipeHECI) Close() {
	p.once.Do(func() { close(p.closed) })
}

// feed delivers a frame to APFConn without panicking if the conn has been torn down.
func (p *pipeHECI) feed(b []byte) {
	select {
	case p.rx <- b:
	case <-p.closed:
	}
}

// openConfirmation builds an APF_CHANNEL_OPEN_CONFIRMATION for the channel opened
// in the given APF_CHANNEL_OPEN frame, granting initialWindow transmit credit.
func openConfirmation(openFrame []byte, amtCh, initialWindow uint32) []byte {
	var om apf.APF_CHANNEL_OPEN_MESSAGE

	_ = binary.Read(bytes.NewReader(openFrame), binary.BigEndian, &om)

	conf := apf.APF_CHANNEL_OPEN_CONFIRMATION_MESSAGE{
		MessageType:       apf.APF_CHANNEL_OPEN_CONFIRMATION,
		RecipientChannel:  om.SenderChannel,
		SenderChannel:     amtCh,
		InitialWindowSize: initialWindow,
		Reserved:          0xFFFFFFFF,
	}

	var b bytes.Buffer

	_ = binary.Write(&b, binary.BigEndian, conf)

	return b.Bytes()
}

// startBridgeDevice runs a fake AMT device that translates between APF frames on
// p and a raw byte stream handed to serve (typically wrapped in a tls.Server).
func startBridgeDevice(t *testing.T, p *pipeHECI, amtCh uint32, serve func(net.Conn)) {
	t.Helper()

	devSide, srvSide := net.Pipe()

	// APF frames from APFConn -> raw stream / control replies.
	go func() {
		for {
			select {
			case frame := <-p.tx:
				switch frame[0] {
				case apf.APF_CHANNEL_OPEN:
					p.feed(openConfirmation(frame, amtCh, apf.LME_RX_WINDOW_SIZE))
				case apf.APF_CHANNEL_DATA:
					var hdr apfChannelDataHeader

					_ = binary.Read(bytes.NewReader(frame), binary.BigEndian, &hdr)

					payload := frame[channelDataHeaderLen : channelDataHeaderLen+int(hdr.Length)]

					if _, err := devSide.Write(payload); err != nil {
						return
					}

					p.feed(apf.BuildChannelWindowAdjustBytes(amtCh, hdr.Length))
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

	// Raw stream bytes from the server -> APFConn as CHANNEL_DATA.
	go func() {
		buf := make([]byte, 4096)

		for {
			n, err := devSide.Read(buf)
			if n > 0 {
				p.feed(apf.BuildChannelDataBytes(amtCh, append([]byte(nil), buf[:n]...)))
			}

			if err != nil {
				return
			}
		}
	}()

	go serve(srvSide)
}

// selfSignedCert generates an ephemeral cert for the fake device's TLS server.
func selfSignedCert(t *testing.T) tls.Certificate {
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

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestAPFConn_TLSRoundTrip drives a real TLS handshake and an application-data
// echo over the APF/HECI channel, exercising Dial, Read, Write, framing, and
// flow control end to end.
func TestAPFConn_TLSRoundTrip(t *testing.T) {
	cert := selfSignedCert(t)
	srvCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	p := newPipeHECI()
	defer p.Close()

	startBridgeDevice(t, p, 9, func(raw net.Conn) {
		srv := tls.Server(raw, srvCfg)
		if err := srv.HandshakeContext(context.Background()); err != nil {
			return
		}

		_, _ = io.Copy(srv, srv)
		_ = srv.Close()
	})

	conn, err := DialAPF(pthi.Command{Heci: p}, 1, utils.LMSTLSPortNum)
	require.NoError(t, err)

	defer conn.Close()

	client := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed AMT cert in test
	require.NoError(t, client.HandshakeContext(context.Background()))

	msg := []byte("hello amt over tls")
	_, err = client.Write(msg)
	require.NoError(t, err)

	got := make([]byte, len(msg))
	_, err = io.ReadFull(client, got)
	require.NoError(t, err)
	assert.Equal(t, msg, got)
}

// TestAPFConn_TLSHTTPRoundTrip validates the PR3 transport shape: an http.Transport
// whose DialTLSContext wraps a fresh APFConn in tls.Client, against a fake device
// that returns a canned HTTP response.
func TestAPFConn_TLSHTTPRoundTrip(t *testing.T) {
	cert := selfSignedCert(t)
	srvCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	p := newPipeHECI()
	defer p.Close()

	startBridgeDevice(t, p, 9, func(raw net.Conn) {
		srv := tls.Server(raw, srvCfg)
		if err := srv.HandshakeContext(context.Background()); err != nil {
			return
		}

		if _, err := http.ReadRequest(bufio.NewReader(srv)); err != nil {
			return
		}

		_, _ = io.WriteString(srv, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
		_ = srv.Close()
	})

	transport := &http.Transport{
		DisableKeepAlives: true,
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			ac, err := DialAPF(pthi.Command{Heci: p}, 1, utils.LMSTLSPortNum)
			if err != nil {
				return nil, err
			}

			tc := tls.Client(ac, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed AMT cert in test
			if err := tc.HandshakeContext(ctx); err != nil {
				_ = ac.Close()

				return nil, err
			}

			return tc, nil
		},
	}

	client := &http.Client{Transport: transport}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://localhost:16993/wsman", nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "OK", string(body))
}

// TestDialAPF_OpenFailure verifies Dial surfaces an APF_CHANNEL_OPEN_FAILURE.
func TestDialAPF_OpenFailure(t *testing.T) {
	p := newPipeHECI()
	defer p.Close()

	go func() {
		frame := <-p.tx
		if frame[0] != apf.APF_CHANNEL_OPEN {
			return
		}

		var fail bytes.Buffer

		_ = binary.Write(&fail, binary.BigEndian, apf.ChannelOpenReplyFailure(1, apf.OPEN_FAILURE_REASON_CONNECT_FAILED))

		p.feed(fail.Bytes())
	}()

	_, err := DialAPF(pthi.Command{Heci: p}, 1, utils.LMSTLSPortNum)
	require.Error(t, err)
}

// TestAPFConn_CloseSendsChannelClose verifies Close emits APF_CHANNEL_CLOSE and
// unblocks readers with an error.
func TestAPFConn_CloseSendsChannelClose(t *testing.T) {
	p := newPipeHECI()
	defer p.Close()

	openFrame := make(chan []byte, 1)

	go func() {
		frame := <-p.tx
		openFrame <- frame

		p.feed(openConfirmation(frame, 9, apf.LME_RX_WINDOW_SIZE))
	}()

	conn, err := DialAPF(pthi.Command{Heci: p}, 1, utils.LMSTLSPortNum)
	require.NoError(t, err)

	<-openFrame // consume the OPEN so the next tx frame is the CLOSE
	require.NoError(t, conn.Close())

	select {
	case frame := <-p.tx:
		assert.Equal(t, byte(apf.APF_CHANNEL_CLOSE), frame[0])
	case <-time.After(2 * time.Second):
		t.Fatal("expected APF_CHANNEL_CLOSE after Close")
	}

	_, err = conn.Read(make([]byte, 8))
	assert.Error(t, err)
}

// TestAPFConn_ReadDeadline verifies a past read deadline returns a timeout error.
func TestAPFConn_ReadDeadline(t *testing.T) {
	p := newPipeHECI()
	defer p.Close()

	go func() {
		frame := <-p.tx
		p.feed(openConfirmation(frame, 9, apf.LME_RX_WINDOW_SIZE))
	}()

	conn, err := DialAPF(pthi.Command{Heci: p}, 1, utils.LMSTLSPortNum)
	require.NoError(t, err)

	defer conn.Close()

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(50*time.Millisecond)))

	_, err = conn.Read(make([]byte, 16))
	require.Error(t, err)

	netErr, ok := err.(net.Error)
	require.True(t, ok)
	assert.True(t, netErr.Timeout())
}

// TestAPFConn_WriteChunksRespectWindow verifies Write never sends more than the
// granted transmit window in one frame and that all bytes arrive intact.
func TestAPFConn_WriteChunksRespectWindow(t *testing.T) {
	p := newPipeHECI()
	defer p.Close()

	const (
		amtCh   = 5
		initWin = 16
	)

	var (
		mu       sync.Mutex
		received []byte
		maxFrame uint32
		frames   int
	)

	deviceDone := make(chan struct{})

	go func() {
		defer close(deviceDone)

		for {
			select {
			case frame := <-p.tx:
				switch frame[0] {
				case apf.APF_CHANNEL_OPEN:
					p.feed(openConfirmation(frame, amtCh, initWin))
				case apf.APF_CHANNEL_DATA:
					var hdr apfChannelDataHeader

					_ = binary.Read(bytes.NewReader(frame), binary.BigEndian, &hdr)

					payload := frame[channelDataHeaderLen : channelDataHeaderLen+int(hdr.Length)]

					mu.Lock()

					received = append(received, payload...)
					frames++

					if hdr.Length > maxFrame {
						maxFrame = hdr.Length
					}
					mu.Unlock()

					p.feed(apf.BuildChannelWindowAdjustBytes(amtCh, hdr.Length))
				case apf.APF_CHANNEL_CLOSE:
					return
				}
			case <-p.closed:
				return
			}
		}
	}()

	conn, err := DialAPF(pthi.Command{Heci: p}, 1, utils.LMSTLSPortNum)
	require.NoError(t, err)

	payload := bytes.Repeat([]byte("x"), 100)

	n, err := conn.Write(payload)
	require.NoError(t, err)
	assert.Equal(t, len(payload), n)

	require.NoError(t, conn.Close())
	p.Close()
	<-deviceDone

	mu.Lock()
	defer mu.Unlock()

	assert.Equal(t, payload, received)
	assert.GreaterOrEqual(t, frames, 2, "payload larger than window should span multiple frames")
	assert.LessOrEqual(t, maxFrame, uint32(initWin), "no frame may exceed the granted window")
}
