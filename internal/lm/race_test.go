package lm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/pthi"
)

// ConcurrentHECI is a thread-safe mock of the HECI driver
// designed to simulate high-throughput traffic to trigger race conditions.
type ConcurrentHECI struct {
	mu            sync.Mutex
	failReceive   bool
	failSend      bool
	failFrequency int // 1 in N chance to fail
}

func (c *ConcurrentHECI) Init(useLME, useWD bool) error { return nil }
func (c *ConcurrentHECI) GetBufferSize() uint32         { return 4096 }

func (c *ConcurrentHECI) SendMessage(buffer []byte, done *uint32) (int, error) {
	// Simulate IO delay
	time.Sleep(time.Duration(rand.Intn(100)) * time.Microsecond)

	if c.failSend && c.failFrequency > 0 && rand.Intn(c.failFrequency) == 0 {
		return 0, errors.New("simulated send error")
	}

	return len(buffer), nil
}

func (c *ConcurrentHECI) ReceiveMessage(buffer []byte, done *uint32) (int, error) {
	// Simulate IO delay
	time.Sleep(time.Duration(rand.Intn(500)) * time.Microsecond)

	if c.failReceive && c.failFrequency > 0 && rand.Intn(c.failFrequency) == 0 {
		return 0, errors.New("simulated receive error")
	}

	// Construct a fake APF CHANNEL DATA packet
	// This simulates the firmware sending data to us.
	// When processed by apf.Process, it will append to Session.Tempdata.

	payload := make([]byte, 128) // Simulation data
	rand.Read(payload)

	// Packet Structure:
	// MessageType (1 byte) = 4 (APF_CHANNEL_DATA)
	// Recipient (1 byte) = 0 (Host)
	// Reserved (2 bytes) - Note: apf package usage in engine.go suggests structs.
	// Let's rely on simplistic byte reconstruction matching what engine.go consumes.
	// engine.go calls: result := apf.Process(result2, lme.Session)

	// We'll construct a valid APF Channel Data packet manually.
	// Reference: APF Protocol
	// APF_CHANNEL_DATA = 4

	msg := new(bytes.Buffer)
	binary.Write(msg, binary.BigEndian, uint8(4))             // APF_CHANNEL_DATA
	binary.Write(msg, binary.BigEndian, uint8(1))             // Recipient Channel (Fake)
	binary.Write(msg, binary.BigEndian, uint16(len(payload))) // Length
	binary.Write(msg, binary.BigEndian, payload)

	data := msg.Bytes()

	// Copy to buffer
	if len(buffer) < len(data) {
		return 0, nil // Should not happen given 4096
	}
	copy(buffer, data)
	*done = uint32(len(data))

	return len(data), nil
}

func (c *ConcurrentHECI) Close() {}

// TestLMERaceCondition stresses the LMEConnection with concurrent sending and receiving.
// Run with 'go test -race -v ./internal/lm/ -run TestLMERaceCondition'
func TestLMERaceCondition(t *testing.T) {
	// Setup channels and waitgroup
	dataCh := make(chan []byte, 1000)
	errCh := make(chan error, 1000)
	wg := &sync.WaitGroup{}

	// Initialize LME Connection
	lme := NewLMEConnection(dataCh, errCh, wg)

	// Inject Concurrent HECI Mock
	lme.Command = pthi.Command{
		Heci: &ConcurrentHECI{},
	}

	// We need to initialize the session to avoid nil pointers if any
	// engine.go Initialize() sets up initial state but we can just skip to Listen/Send
	// for purely testing the Session buffer race.

	// Start the Listen loop (Simulating the receiver goroutine)
	// This will also spawn the Timer goroutine internally.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Recovered from panic in Listen: %v", r)
			}
		}()
		lme.Listen()
	}()

	// Start concurrent Senders (Simulating the application sending data)
	// Each Send modifies lme.Session.TXWindow (read/write)
	senderCount := 10
	iterations := 500
	var senderWg sync.WaitGroup

	senderWg.Add(senderCount)
	for i := 0; i < senderCount; i++ {
		go func() {
			defer senderWg.Done()
			payload := []byte("simulate sending data to firmware")
			for j := 0; j < iterations; j++ {
				// Random sleep to interleave operations
				time.Sleep(time.Duration(rand.Intn(500)) * time.Microsecond)

				// This accesses Session state (TXWindow)
				err := lme.Send(payload)
				if err != nil {
					// Ignore errors from mock
				}
			}
		}()
	}

	// Wait for senders to finish
	senderWg.Wait()

	// Close connection to stop Listen loop (mocks handling close is trivial)
	lme.Close()

	// Pass if no panic occurred (managed by testing framework + race detector)
}

// TestLMEConcurrentErrors simulates IO errors during concurrent operations
// to ensure no deadlocks or panics occur when the driver fails.
func TestLMEConcurrentErrors(t *testing.T) {
	// Setup channels
	dataCh := make(chan []byte, 100)
	errCh := make(chan error, 100)
	wg := &sync.WaitGroup{}

	lme := NewLMEConnection(dataCh, errCh, wg)

	// Inject Failing Concurrent HECI Mock
	lme.Command = pthi.Command{
		Heci: &ConcurrentHECI{
			failSend:      true,
			failReceive:   true,
			failFrequency: 10, // Fail ~10% of the time
		},
	}

	// Start reading loop
	go func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Recovered from panic in Listen: %v", r)
			}
		}()
		lme.Listen()
	}()

	// Start concurrent senders experiencing errors
	var senderWg sync.WaitGroup
	senderWg.Add(5)
	for i := 0; i < 5; i++ {
		go func() {
			defer senderWg.Done()
			payload := []byte("data")
			for j := 0; j < 100; j++ {
				// We expect errors here, just ensure no panic/deadlock
				lme.Send(payload)
				time.Sleep(time.Duration(rand.Intn(100)) * time.Microsecond)
			}
		}()
	}

	senderWg.Wait()

	// Ensure we can close cleanly even with pending errors
	lme.Close()
}
