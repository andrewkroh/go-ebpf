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

package exec_test

import (
	"os"
	execute "os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/andrewkroh/go-ebpf/exec"
)

func TestNewMonitor(t *testing.T) {
	// Start the exec syscall monitor.
	m, err := exec.NewMonitor()
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	eventsC, err := m.Start(done)
	if err != nil {
		t.Fatal(err)
	}

	// Run ls -la to generate some known events.
	cmd := execute.Command("ls", "-la")
	_, err = cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid

	// Stop monitoring after one second.
	time.AfterFunc(time.Second, func() {
		close(done)
	})

	selfPID := os.Getpid()
	var started *exec.ProcessStarted
	var exited *exec.ProcessExited

	for e := range eventsC {
		switch v := e.(type) {
		case exec.ProcessStarted:
			if v.PID == uint32(pid) {
				started = &v
				t.Logf("%+v", v)
			} else if v.PID == uint32(selfPID) {
				t.Logf("%+v", v)
			}
		case exec.ProcessExited:
			if v.PID == uint32(pid) {
				exited = &v
				t.Logf("%+v", v)
			}
		}
	}

	if started == nil {
		t.Fatal("Did not receive started event for PID %v", pid)
	}
	if exited == nil {
		t.Fatal("Did not receive exited event for PID %v", pid)
	}

	// Start and stop times.
	assert.True(t, time.Since(exited.StartTime) < 5*time.Second)
	assert.True(t, exited.EndTime.After(exited.StartTime))

	// Parent process info which is this tester.
	assert.EqualValues(t, selfPID, exited.PPID)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe = filepath.Base(exe)
	assert.Equal(t, exe, exited.ParentComm)

	// ls -la process info.
	assert.EqualValues(t, os.Getuid(), exited.UID)
	assert.EqualValues(t, os.Getgid(), exited.GID)
	assert.Equal(t, "/bin/ls", exited.Exe)
	assert.Equal(t, []string{"ls", "-la"}, exited.Args)
}
