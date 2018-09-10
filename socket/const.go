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

import "strconv"

type TCPState uint32

// Linux TCP states.
// https://elixir.bootlin.com/linux/latest/source/include/net/tcp_states.h#L16
const (
	TCP_ESTABLISHED TCPState = iota + 1
	TCP_SYN_SENT
	TCP_SYN_RECV
	TCP_FIN_WAIT1
	TCP_FIN_WAIT2
	TCP_TIME_WAIT
	TCP_CLOSE
	TCP_CLOSE_WAIT
	TCP_LAST_ACK
	TCP_LISTEN
	TCP_CLOSING // Now a valid state
	TCP_NEW_SYN_RECV

	TCP_MAX_STATES /* Leave at the end! */
)

var tcpStateNames = map[TCPState]string{
	TCP_ESTABLISHED:  "ESTABLISHED",
	TCP_SYN_SENT:     "SYN_SENT",
	TCP_SYN_RECV:     "SYN_RECV",
	TCP_FIN_WAIT1:    "FIN_WAIT1",
	TCP_FIN_WAIT2:    "FIN_WAIT2",
	TCP_TIME_WAIT:    "TIME_WAIT",
	TCP_CLOSE:        "CLOSE",
	TCP_CLOSE_WAIT:   "CLOSE_WAIT",
	TCP_LAST_ACK:     "LAST_ACK",
	TCP_LISTEN:       "LISTEN",
	TCP_CLOSING:      "CLOSING", // Now a valid state
	TCP_NEW_SYN_RECV: "NEW_SYNC_RECV",
}

func (s TCPState) String() string {
	name, found := tcpStateNames[s]
	if found {
		return name
	}
	return "unknown (" + strconv.Itoa(int(s)) + ")"
}

func (s TCPState) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

type AddressFamily uint16

// https://elixir.bootlin.com/linux/latest/source/include/linux/socket.h#L160
const (
	AF_UNSPEC     = 0
	AF_UNIX       = 1
	AF_INET       = 2
	AF_AX25       = 3
	AF_IPX        = 4
	AF_APPLETALK  = 5
	AF_NETROM     = 6
	AF_BRIDGE     = 7
	AF_ATMPVC     = 8
	AF_X25        = 9
	AF_INET6      = 10
	AF_ROSE       = 11
	AF_DECnet     = 12
	AF_NETBEUI    = 13
	AF_SECURITY   = 14
	AF_KEY        = 15
	AF_NETLINK    = 16
	AF_PACKET     = 17
	AF_ASH        = 18
	AF_ECONET     = 19
	AF_ATMSVC     = 20
	AF_RDS        = 21
	AF_SNA        = 22
	AF_IRDA       = 23
	AF_PPPOX      = 24
	AF_WANPIPE    = 25
	AF_LLC        = 26
	AF_IB         = 27
	AF_MPLS       = 28
	AF_CAN        = 29
	AF_TIPC       = 30
	AF_BLUETOOTH  = 31
	AF_IUCV       = 32
	AF_RXRPC      = 33
	AF_ISDN       = 34
	AF_PHONET     = 35
	AF_IEEE802154 = 36
	AF_CAIF       = 37
	AF_ALG        = 38
	AF_NFC        = 39
	AF_VSOCK      = 40
	AF_KCM        = 41
	AF_QIPCRTR    = 42
	AF_SMC        = 43
	AF_XDP        = 44
)

var addressFamilyNames = map[AddressFamily]string{
	AF_UNSPEC:     "UNSPEC",
	AF_UNIX:       "UNIX",
	AF_INET:       "INET",
	AF_AX25:       "AX25",
	AF_IPX:        "IPX",
	AF_APPLETALK:  "APPLETALK",
	AF_NETROM:     "NETROM",
	AF_BRIDGE:     "BRIDGE",
	AF_ATMPVC:     "ATMPVC",
	AF_X25:        "X25",
	AF_INET6:      "INET6",
	AF_ROSE:       "ROSE",
	AF_DECnet:     "DECnet",
	AF_NETBEUI:    "NETBEUI",
	AF_SECURITY:   "SECURITY",
	AF_KEY:        "KEY",
	AF_NETLINK:    "NETLINK",
	AF_PACKET:     "PACKET",
	AF_ASH:        "ASH",
	AF_ECONET:     "ECONET",
	AF_ATMSVC:     "ATMSVC",
	AF_RDS:        "RDS",
	AF_SNA:        "SNA",
	AF_IRDA:       "IRDA",
	AF_PPPOX:      "PPPOX",
	AF_WANPIPE:    "WANPIPE",
	AF_LLC:        "LLC",
	AF_IB:         "IB",
	AF_MPLS:       "MPLS",
	AF_CAN:        "CAN",
	AF_TIPC:       "TIPC",
	AF_BLUETOOTH:  "BLUETOOTH",
	AF_IUCV:       "IUCV",
	AF_RXRPC:      "RXRPC",
	AF_ISDN:       "ISDN",
	AF_PHONET:     "PHONET",
	AF_IEEE802154: "IEEE802154",
	AF_CAIF:       "CAIF",
	AF_ALG:        "ALG",
	AF_NFC:        "NFC",
	AF_VSOCK:      "VSOCK",
	AF_KCM:        "KCM",
	AF_QIPCRTR:    "QIPCRTR",
	AF_SMC:        "SMC",
	AF_XDP:        "XDP",
}

func (af AddressFamily) String() string {
	name, found := addressFamilyNames[af]
	if found {
		return name
	}
	return "unknown (" + strconv.Itoa(int(af)) + ")"
}

func (af AddressFamily) MarshalText() ([]byte, error) { return []byte(af.String()), nil }

type IPProtocol uint8

const (
	IPPROTO_IP      = 0
	IPPROTO_ICMP    = 1
	IPPROTO_IGMP    = 2
	IPPROTO_IPIP    = 4
	IPPROTO_TCP     = 6
	IPPROTO_EGP     = 8
	IPPROTO_PUP     = 12
	IPPROTO_UDP     = 17
	IPPROTO_IDP     = 22
	IPPROTO_TP      = 29
	IPPROTO_DCCP    = 33
	IPPROTO_IPV6    = 41
	IPPROTO_RSVP    = 46
	IPPROTO_GRE     = 47
	IPPROTO_ESP     = 50
	IPPROTO_AH      = 51
	IPPROTO_MTP     = 92
	IPPROTO_BEETPH  = 94
	IPPROTO_ENCAP   = 98
	IPPROTO_PIM     = 103
	IPPROTO_COMP    = 108
	IPPROTO_SCTP    = 132
	IPPROTO_UDPLITE = 136
	IPPROTO_MPLS    = 137
	IPPROTO_RAW     = 255
)

var ipProtocolNames = map[IPProtocol]string{
	IPPROTO_IP:      "IP",
	IPPROTO_ICMP:    "ICMP",
	IPPROTO_IGMP:    "IGMP",
	IPPROTO_IPIP:    "IPIP",
	IPPROTO_TCP:     "TCP",
	IPPROTO_EGP:     "EGP",
	IPPROTO_PUP:     "PUP",
	IPPROTO_UDP:     "UDP",
	IPPROTO_IDP:     "IDP",
	IPPROTO_TP:      "TP",
	IPPROTO_DCCP:    "DCCP",
	IPPROTO_IPV6:    "IPV6",
	IPPROTO_RSVP:    "RSVP",
	IPPROTO_GRE:     "GRE",
	IPPROTO_ESP:     "ESP",
	IPPROTO_AH:      "AH",
	IPPROTO_MTP:     "MTP",
	IPPROTO_BEETPH:  "BEETPH",
	IPPROTO_ENCAP:   "ENCAP",
	IPPROTO_PIM:     "PIM",
	IPPROTO_COMP:    "COMP",
	IPPROTO_SCTP:    "SCTP",
	IPPROTO_UDPLITE: "UDPLITE",
	IPPROTO_MPLS:    "MPLS",
	IPPROTO_RAW:     "RAW",
}

func (p IPProtocol) String() string {
	name, found := ipProtocolNames[p]
	if found {
		return name
	}
	return "unknown (" + strconv.Itoa(int(p)) + ")"
}

func (p IPProtocol) MarshalText() ([]byte, error) { return []byte(p.String()), nil }
