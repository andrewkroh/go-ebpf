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

// Code generated by bin_data.go - DO NOT EDIT.

package socket

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
)

var assets map[string][]byte

func asset(key string) ([]byte, error) {
	if assets == nil {
		assets = map[string][]byte{}

		var value []byte
		value, _ = base64.StdEncoding.DecodeString("H4sIAAAAAAAC/+xUPWgUQRT+dm/P21xErxA5L0GFFAaLS9DCSogBtUkhgvW6WSZ6JNnE3SUxJiCCNsFGxMYqgkXsUgS0EDaFhUUKCwuLFBYWKURSCIo/GZmZN97e3G7SWPrg9rvvm/e9t/tmZ+9eHLtkWxZ0WPiGNmvHWrn9f4SuvbCQHlXaAwAugLTS5sKyWF3hgi/4rtQXG6tcrx8CMA/gJICguib1lyoNwfIGV/ia8BXh+l//4Q7/mw49qL6l/G3CT4QfCbcIPxC+J3xHuCmx5dfl/Uw2PhNvEP8iue/X1P02dogfIf6V8vsp/7vkt8aPSx6f/iF5vLxL+JvwF+FPQi4xfaHmUukBtjjn6TPiFrAp+CpxF1jnnF+ze1AVvoD0EnBKzNcGajQnx1g/J/gjxXVeGWpDsnknaN0pqDNg1OnIu9dZX+gCb1TUPs4Tps+pngOsiOfzFa/bne9lGlO9MnCd6h0TnNafEDqZn7r8DxGXr4xhl3Ne0+f/zlW4S71WH+1LnfRVe+86j+W1hG3j4/GQ9MEcfwmlLo3Jvge69IbUK136QamXu/QBqXfXn7X1dw6ySz/pVXk/AJoJu51g2p+Nh+KZYJIlHptjYRLDm2NR3JoJkUR+wLxWyBJPZHix+JP4CUMzYlNydXamFSbSP5SX5021AhbGytBkN72JyJ9maMZJlPjjaMYL0wLHRkeHvbMKzvyj/V7Sz2lEjUb41NCtHK5nl42Rgn7mUbuwj998z1wj7zyAnpw+O9SoZuyn9mu9Qv3NGWxT37q19/1PFPh1orPP/PoK/E6B3+QR+c3j5FLiIPaeX1gwP32EsvNzc+Z3P6e3iGHqv5F5bifj19+RPwAAAP//AQAA//8AdMIocAgAAA==")
		value, _ = gzipDecode(value)
		assets["socket.o"] = value
	}

	if value, found := assets[key]; found {
		return value, nil
	}
	return nil, fmt.Errorf("asset not found for key=%v", key)
}

func gzipDecode(data []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	out := new(bytes.Buffer)
	if _, err = io.Copy(out, gz); err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}
