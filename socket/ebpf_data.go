// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package socket

import (
	"bytes"
	"encoding/binary"
	"time"
)

type ipStateData struct {
	KTimeNS       time.Duration
	ID            uint64
	PID           uint32
	Comm          [16]byte
	UID           uint32
	GID           uint32
	SrcAddr       [16]byte
	DstAddr       [16]byte
	SrcPort       uint16
	DstPort       uint16
	OldState      TCPState
	NewState      TCPState
	AddressFamily AddressFamily
	Protocol      IPProtocol
	_             [5]byte
}

func unmarshalData(data []byte) (ipStateData, error) {
	var event ipStateData
	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event)
	return event, err
}
