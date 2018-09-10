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
	"net"
	"time"
)

type IPState struct {
	Timestamp     time.Time     `json:"timestamp"`
	ID            uint64        `json:"id"`
	PID           uint32        `json:"pid"`
	Comm          string        `json:"comm"`
	UID           uint32        `json:"uid"`
	GID           uint32        `json:"gid"`
	SrcAddr       net.IP        `json:"source_ip"`
	DstAddr       net.IP        `json:"destination_ip"`
	SrcPort       uint16        `json:"source_port,omitempty"`
	DstPort       uint16        `json:"destination_port,omitempty"`
	OldState      TCPState      `json:"state_old"`
	NewState      TCPState      `json:"state_new"`
	AddressFamily AddressFamily `json:"address_family"`
	Protocol      IPProtocol    `json:"network_protocol"`
}
