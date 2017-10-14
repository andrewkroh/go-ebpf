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
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/andrewkroh/go-ebpf/common"
)

var (
	sizeofExecveData = int(unsafe.Sizeof(ExecveData{}))
	sizeofExecveArg  = int(unsafe.Sizeof(ExecveArg{}))
	sizeofExecveRtn  = int(unsafe.Sizeof(ExecveRtn{}))
)

type ExecveData struct {
	PID  uint32
	UID  uint32
	GID  uint32
	_    uint32
	Comm [16]byte
}

func (e ExecveData) String() string {
	return fmt.Sprintf("pid:%d, uid:%d, gid:%d, comm:%s",
		e.PID, e.UID, e.GID, common.NullTerminatedString(e.Comm[:]))
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
