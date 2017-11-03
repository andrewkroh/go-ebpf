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

import "time"

//  Event Types

// processData is common to all events that are published. Fields tagged with
// omitempty are optional data.
type processData struct {
	StartTime time.Time `json:"start_time"`

	PPID       uint32 `json:"ppid"`
	ParentComm string `json:"parent_comm,omitempty"`

	PID  uint32   `json:"pid"`
	UID  uint32   `json:"uid"`
	GID  uint32   `json:"gid"`
	Comm string   `json:"comm,omitempty"`
	Exe  string   `json:"exe,omitempty"`
	Args []string `json:"args,omitempty"`
}

// Proc
type ProcessStarted struct {
	Type string `json:"type"`
	processData
}

type ProcessExited struct {
	Type string `json:"type"`
	processData
	EndTime     time.Time     `json:"end_time"`
	RunningTime time.Duration `json:"running_time_ns"`
}

type ProcessError struct {
	Type string `json:"type"`
	processData
	ErrorCode int32 `json:"error_code"`
}
