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

// +build linux

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/Sirupsen/logrus"

	"github.com/andrewkroh/go-ebpf/exec"
)

var log = logrus.WithField("selector", "main")

func main() {
	flag.Parse()

	// Start the exec syscall monitor.
	m, err := exec.NewMonitor()
	if err != nil {
		log.WithError(err).Fatal("failed to create exec monitor")
	}

	done := make(chan struct{})
	events, err := m.Start(done)
	if err != nil {
		log.WithError(err).Fatal("failed to start exec monitor")
	}

	// Handle signals for shutting down.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	go func() {
		<-sig
		close(done)
	}()

	// Read incoming exec events.
	for e := range events {
		data, _ := json.Marshal(e)
		fmt.Println(string(data))
	}
}
