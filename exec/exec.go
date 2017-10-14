/*
 * Copyright 2017 Elasticsearch Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package exec

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/Sirupsen/logrus"
	bpf "github.com/iovisor/gobpf/elf"
	"github.com/pkg/errors"

	"github.com/andrewkroh/go-ebpf/common"
)

const (
	execveProbe       = "kprobe/SyS_execve"
	execveReturnProbe = "kretprobe/SyS_execve"
	execveMap         = "execve_events"
)

var log = logrus.WithField("selector", "exec")

type ExecveEvent struct {
	PID        uint32   `json:"pid"`
	UID        uint32   `json:"uid"`
	GID        uint32   `json:"gid"`
	ParentComm string   `json:"parent_comm"`
	Exe        string   `json:"exe"`
	Arguments  []string `json:"args"`
	ReturnCode int32    `json:"return_code"`
}

func (e ExecveEvent) String() string {
	return fmt.Sprintf("PID:%d, UID:%d, GID:%d, ParentComm:%s, "+
		"Exe:%s, Arguments:[%s], ReturnCode:%d",
		e.PID, e.UID, e.GID, e.ParentComm, e.Exe,
		strings.Join(e.Arguments, " "), e.ReturnCode)
}

type ExecMonitor struct {
	module        *bpf.Module
	execvePerfMap *bpf.PerfMap
	events        chan []byte
	lostEvents    chan uint64

	execveSyscalls map[uint32]*ExecveEvent
	lostCount      uint64
	output         chan ExecveEvent
	done           <-chan struct{}
}

func NewMonitor() *ExecMonitor {
	return &ExecMonitor{
		execveSyscalls: map[uint32]*ExecveEvent{},
	}
}

func (m *ExecMonitor) Start(done <-chan struct{}) (<-chan ExecveEvent, error) {
	if err := m.init(); err != nil {
		return nil, err
	}
	m.output = make(chan ExecveEvent, 1)

	go func() {
		defer close(m.output)
		defer m.execvePerfMap.PollStop()
		defer m.module.Close()

		for {
			select {
			case data := <-m.events:
				m.processData(data)
			case count := <-m.lostEvents:
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

func (m *ExecMonitor) init() error {
	data, err := asset("exec.o")
	if err != nil {
		return errors.Wrap(err, "failed to load embedded ebpf code")
	}

	// Load module to kernel.
	m.module = bpf.NewModuleFromReader(bytes.NewReader(data))
	if err := m.module.Load(nil); err != nil {
		return errors.Wrap(err, "failed to load ebpf module to kernel")
	}

	// Setup our perf event readers.
	m.events = make(chan []byte, 64)
	m.lostEvents = make(chan uint64, 1)
	m.execvePerfMap, err = bpf.InitPerfMap(m.module, execveMap, m.events, m.lostEvents)
	if err != nil {
		m.module.Close()
		return errors.Wrapf(err, "failed to initialize %v perf map", execveMap)
	}

	// Enable the kprobes.
	if err := m.module.EnableKprobe(execveProbe, 0); err != nil {
		m.module.Close()
		return errors.Wrapf(err, "failed to enable %v probe", execveProbe)
	}

	if err := m.module.EnableKprobe(execveReturnProbe, 0); err != nil {
		m.module.Close()
		return errors.Wrapf(err, "failed to enable %v probe", execveReturnProbe)
	}

	m.execvePerfMap.PollStart()
	return nil
}

func (m *ExecMonitor) processData(data []byte) {
	switch len(data) {
	case sizeofExecveData:
		event, err := unmarshalData(data)
		if err != nil {
			log.WithError(err).Warn("failed to unmarshal execve data")
			return
		}

		m.execveSyscalls[event.PID] = &ExecveEvent{
			PID:        event.PID,
			UID:        event.UID,
			GID:        event.GID,
			ParentComm: common.NullTerminatedString(event.Comm[:]),
		}
	case sizeofExecveArg:
		event, err := unmarshalArg(data)
		if err != nil {
			log.WithError(err).Warn("failed to unmarshal execve arg")
			return
		}

		e, found := m.execveSyscalls[event.PID]
		if !found {
			return
		}

		arg := common.NullTerminatedString(event.Arg[:])
		if len(e.Exe) == 0 {
			e.Exe = arg
		} else {
			e.Arguments = append(e.Arguments, arg)
		}
	case sizeofExecveRtn:
		event, err := unmarshalRtn(data)
		if err != nil {
			log.WithError(err).Warn("failed to unmarshal execve return")
			return
		}

		e, found := m.execveSyscalls[event.PID]
		if !found {
			return
		}
		delete(m.execveSyscalls, event.PID)
		e.ReturnCode = event.ReturnCode

		// Output event.
		select {
		case <-m.done:
		case m.output <- *e:
		}
	}
}
