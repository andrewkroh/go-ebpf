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
	"net"
	"time"

	"github.com/Sirupsen/logrus"
	bpf "github.com/iovisor/gobpf/elf"
	"github.com/pkg/errors"
	"github.com/prometheus/procfs"

	"github.com/andrewkroh/go-ebpf/common"
)

// probe and map names in the eBPF program.
const (
	sockStateTracepoint = "tracepoint/sock/inet_sock_set_state"
	socketEventsMap     = "socket_events"
)

var log = logrus.WithField("selector", "socket")

type Monitor struct {
	// eBPF
	module        *bpf.Module
	execvePerfMap *bpf.PerfMap
	bpfEvents     chan []byte
	lostBPFEvents chan uint64
	lostCount     uint64

	// internal state
	bootTime time.Time
	procfs   procfs.FS

	output chan interface{}
	done   <-chan struct{}
}

func NewMonitor() (*Monitor, error) {
	procfs, err := procfs.NewFS(procfs.DefaultMountPoint)
	if err != nil {
		return nil, err
	}

	// Fetch and cache the boot time.
	stat, err := procfs.NewStat()
	if err != nil {
		return nil, err
	}

	return &Monitor{
		bootTime: time.Unix(int64(stat.BootTime), 0),
		procfs:   procfs,
	}, nil
}

func (m *Monitor) Start(done <-chan struct{}) (<-chan interface{}, error) {
	if err := m.initBPF(); err != nil {
		return nil, err
	}
	m.output = make(chan interface{}, 1)

	go func() {
		defer close(m.output)
		defer m.execvePerfMap.PollStop()
		defer m.module.Close()

		for {
			select {
			case data := <-m.bpfEvents:
				m.handleBPFData(data)
			case count := <-m.lostBPFEvents:
				m.lostCount += count
				log.WithField("total_dropped", m.lostCount).Infof(
					"%v messages from kernel dropped", count)
			case <-done:
				return
			}
		}
	}()

	return m.output, nil
}

func (m *Monitor) initBPF() error {
	data, err := asset("socket.o")
	if err != nil {
		return errors.Wrap(err, "failed to load embedded ebpf code")
	}

	// Load module to kernel.
	m.module = bpf.NewModuleFromReader(bytes.NewReader(data))
	if err := m.module.Load(nil); err != nil {
		return errors.Wrap(err, "failed to load ebpf module to kernel")
	}

	// Setup our perf event readers.
	m.bpfEvents = make(chan []byte, 64)
	m.lostBPFEvents = make(chan uint64, 1)
	m.execvePerfMap, err = bpf.InitPerfMap(m.module, socketEventsMap, m.bpfEvents, m.lostBPFEvents)
	if err != nil {
		m.module.Close()
		return errors.Wrapf(err, "failed to initialize %v perf map", socketEventsMap)
	}

	// Enable the tracepoint.
	if err := m.module.EnableTracepoint(sockStateTracepoint); err != nil {
		m.module.Close()
		return errors.Wrapf(err, "failed to enable %v tracepoint", sockStateTracepoint)
	}

	m.execvePerfMap.PollStart()
	return nil
}

func (m *Monitor) handleBPFData(data []byte) {
	state, err := unmarshalData(data)
	if err != nil {
		log.WithError(err).Warn("failed to unmarshal ip state data")
		return
	}

	var srcIP, dstIP net.IP
	if state.Protocol == AF_INET6 {
		srcIP = net.IP(state.SrcAddr[:])
		dstIP = net.IP(state.DstAddr[:])
	} else {
		srcIP = net.IP(state.SrcAddr[:4])
		dstIP = net.IP(state.DstAddr[:4])
	}

	s := &IPState{
		Timestamp:     m.bootTime.Add(state.KTimeNS),
		ID:            state.ID,
		PID:           state.PID,
		Comm:          common.NullTerminatedString(state.Comm[:]),
		UID:           state.UID,
		GID:           state.GID,
		SrcAddr:       srcIP,
		DstAddr:       dstIP,
		SrcPort:       state.SrcPort,
		DstPort:       state.DstPort,
		OldState:      state.OldState,
		NewState:      state.NewState,
		AddressFamily: state.AddressFamily,
		Protocol:      state.Protocol,
	}

	m.publish(s)
}

func (m *Monitor) publish(event *IPState) {
	select {
	case <-m.done:
	case m.output <- event:
	}
}
