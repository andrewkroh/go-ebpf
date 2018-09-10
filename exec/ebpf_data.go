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

package exec

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
	"unsafe"

	"github.com/andrewkroh/go-ebpf/common"
)

var (
	sizeofExecveData = int(unsafe.Sizeof(ExecveData{}))
	sizeofExecveArg  = int(unsafe.Sizeof(ExecveArg{}))
	sizeofExecveRtn  = int(unsafe.Sizeof(ExecveRtn{}))
	sizeofExitData   = int(unsafe.Sizeof(ExitData{}))
)

type ExecveData struct {
	KTimeNS         time.Duration
	RealStartTimeNS time.Duration
	PID             uint32
	UID             uint32
	GID             uint32
	PPID            uint32
	Comm            [16]byte
}

func (e ExecveData) String() string {
	return fmt.Sprintf("ktime:%d, real_start_time:%d, pid:%d, uid:%d, gid:%d, ppid:%d, comm:%s",
		e.KTimeNS, e.RealStartTimeNS, e.PID, e.UID, e.GID, e.PPID, common.NullTerminatedString(e.Comm[:]))
}

type ExecveArg struct {
	PID uint32
	_   uint32
	Arg [256]byte
}

func (e ExecveArg) String() string {
	return fmt.Sprintf("pid:%d, arg:%s", e.PID, common.NullTerminatedString(e.Arg[:]))
}

type ExecveRtn struct {
	PID        uint32
	ReturnCode int32
}

func (e ExecveRtn) String() string {
	return fmt.Sprintf("pid:%d, rtn:%d", e.PID, e.ReturnCode)
}

type ExitData struct {
	KTime uint64
	PID   uint32
}

func (e ExitData) String() string {
	return fmt.Sprintf("ktime:%d, pid:%d", e.KTime, e.PID)
}

func unmarshalData(data []byte) (ExecveData, error) {
	var event ExecveData
	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event)
	return event, err
}

func unmarshalArg(data []byte) (ExecveArg, error) {
	var event ExecveArg
	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event)
	return event, err
}

func unmarshalRtn(data []byte) (ExecveRtn, error) {
	var event ExecveRtn
	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event)
	return event, err
}

func unmarshalExitData(data []byte) (ExitData, error) {
	var event ExitData
	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event)
	return event, err
}
