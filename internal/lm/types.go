/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package lm

// StreamEvent belongs to one LMS socket generation. Data and terminal events share
// a channel so EOF cannot overtake the final bytes read from that socket.
type StreamEvent struct {
	Generation uint64
	Data       []byte
	Err        error
}

type TLSStreamReader interface {
	StartTLSStream() (uint64, <-chan StreamEvent)
}

type LocalMananger interface {
	Initialize() error
	Connect() error
	Listen()
	Send(data []byte) error
	Close() error
}
