// Copyright (c) 2014 Dataence, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sequence

import (
	"fmt"
	"testing"

	"github.com/dataence/assert"
)

var (
	analyzerSshdSamples []string = []string{
		"Jan 12 06:49:42 irc sshd[7034]: Failed password for root from 218.161.81.238 port 4228 ssh2",
		"Jan 12 06:49:42 irc sshd[7034]: Accepted password for root from 218.161.81.238 port 4228 ssh2",
		"Jan 12 14:44:48 jlz sshd[11084]: Accepted publickey for jlz from 76.21.0.16 port 36609 ssh2",
	}

	analyzerSshdPatterns []string = []string{
		"%ts% %string% sshd [ %integer% ] : %string% %string% for %string% from %ipv4% port %integer% ssh2",
		"%ts% %string% sshd [ %integer% ] : %string% %string% for %string% from %ipv4% port %integer% ssh2",
		"%ts% %string% sshd [ %integer% ] : %string% %string% for %string% from %ipv4% port %integer% ssh2",
	}

	analyzerKeyValueSamples []string = []string{
		"id=firewall time=\"2005-03-18 14:01:46\" fw=TOPSEC priv=6 recorder=kernel type=conn policy=414 proto=TCP rule=accept src=61.167.71.244 sport=35223 dst=210.82.119.211 dport=25 duration=27 inpkt=37 outpkt=39 sent=1770 rcvd=20926 smac=00:04:c1:8b:d8:82 dmac=00:0b:5f:b2:1d:80",
		"id=firewall time=\"2005-03-18 14:01:43\" fw=TOPSEC priv=4 recorder=kernel type=conn policy=504 proto=TCP rule=deny src=210.82.121.91 sport=4958 dst=61.229.37.85 dport=23124 smac=00:0b:5f:b2:1d:80 dmac=00:04:c1:8b:d8:82",
	}

	analyzerKeyValuePatterns []string = []string{
		"id = %string% time = \" %ts% \" fw = %string% priv = %integer% recorder = %string% type = %string% policy = %integer% proto = %string% rule = %string% src = %ipv4% sport = %integer% dst = %ipv4% dport = %integer% duration = %integer% inpkt = %integer% outpkt = %integer% sent = %integer% rcvd = %integer% smac = %mac% dmac = %mac%",
		"id = %string% time = \" %ts% \" fw = %string% priv = %integer% recorder = %string% type = %string% policy = %integer% proto = %string% rule = %string% src = %ipv4% sport = %integer% dst = %ipv4% dport = %integer% smac = %mac% dmac = %mac%",
	}
)

func TestAnalyzerMergeNodes(t *testing.T) {
	atree := NewAnalyzer()
	msg := &message{}

	for _, data := range analyzerSshdSamples {
		msg.data = data
		err := msg.tokenize()
		assert.NoError(t, true, err)
		atree.Add(msg.tokens)
	}

	l := 0

	for i := 1; i < numAllTypes; i++ {
		node := atree.levels[l][i]

		if i == numFieldTypes+int(TokenTS) {
			assert.NotNil(t, true, node, fmt.Sprintf("Expected: levels[%d][TokenTS] != nil, Actual: got nil", l))
		} else {
			assert.Nil(t, true, node, fmt.Sprintf("Expected: levels[%d][%d] == nil, Actual: got non-nil %s", l, i, node))
		}
	}

	assert.Equal(t, true, 0, len(atree.litmaps[l]), fmt.Sprintf("Expected: levels[%d].litmap == 0, Actual: got %d", l, len(atree.litmaps[l])))

	l = 1

	for i := 1; i < minFixedChildren; i++ {
		node := atree.levels[l][i]

		assert.Nil(t, true, node, fmt.Sprintf("Expected: levels[%d][%d] == nil, Actual: got non-nil %s", l, i, node))
	}

	if len(atree.litmaps[l]) != 2 {
		t.Fatalf("Expected: levels[%d].litmap == 2, Actual: got %d", l, len(atree.litmaps[l]))
	}

	l = 2

	for i := 1; i < minFixedChildren; i++ {
		node := atree.levels[l][i]

		assert.Nil(t, true, node, fmt.Sprintf("Expected: levels[%d][%d] == nil, Actual: got non-nil %s", l, i, node))
	}

	assert.Equal(t, true, 1, len(atree.litmaps[l]), fmt.Sprintf("Expected: levels[%d].litmap == 1, Actual: got %d", l, len(atree.litmaps[l])))

	l = 4

	for i := 1; i < minFixedChildren; i++ {
		node := atree.levels[l][i]

		if i == numFieldTypes+int(TokenInteger) {
			assert.NotNil(t, true, node, fmt.Sprintf("Expected: levels[%d][TokenInteger] != nil, Actual: got nil", l))
		} else {
			assert.Nil(t, true, node, fmt.Sprintf("Expected: levels[%d][%d] == nil, Actual: got non-nil %s", l, i, node))
		}
	}

	assert.Equal(t, true, 0, len(atree.litmaps[l]), fmt.Sprintf("Expected: levels[%d].litmap == 0, Actual: got %d", l, len(atree.litmaps[l])))

	l = 7

	for i := 1; i < minFixedChildren; i++ {
		node := atree.levels[l][i]

		assert.Nil(t, true, node, fmt.Sprintf("Expected: levels[%d][%d] == nil, Actual: got non-nil %s", l, i, node))
	}

	assert.Equal(t, true, 2, len(atree.litmaps[l]), fmt.Sprintf("Expected: levels[%d].litmap == 2, Actual: got %d", l, len(atree.litmaps[l])))

	l = 8

	for i := 1; i < minFixedChildren; i++ {
		node := atree.levels[l][i]

		assert.Nil(t, true, node, fmt.Sprintf("Expected: levels[%d][%d] == nil, Actual: got non-nil %s", l, i, node))
	}

	assert.Equal(t, true, 2, len(atree.litmaps[l]), fmt.Sprintf("Expected: levels[%d].litmap == 2, Actual: got %d", l, len(atree.litmaps[l])))

	l = 12

	for i := 1; i < numAllTypes; i++ {
		node := atree.levels[l][i]

		if i == numFieldTypes+int(TokenIPv4) {
			assert.NotNil(t, true, node, fmt.Sprintf("Expected: levels[%d][TokenIPv4] != nil, Actual: got nil", l))
		} else {
			assert.Nil(t, true, node, fmt.Sprintf("Expected: levels[%d][%d] == nil, Actual: got non-nil %s", l, i, node))
		}
	}

	assert.Equal(t, true, 0, len(atree.litmaps[l]), fmt.Sprintf("Expected: levels[%d].litmap == 0, Actual: got %d", l, len(atree.litmaps[l])))

	l = 14

	for i := 1; i < minFixedChildren; i++ {
		node := atree.levels[l][i]

		if i == numFieldTypes+int(TokenInteger) {
			assert.NotNil(t, true, node, fmt.Sprintf("Expected: levels[%d][TokenInteger] != nil, Actual: got nil", l))
		} else {
			assert.Nil(t, true, node, fmt.Sprintf("Expected: levels[%d][%d] == nil, Actual: got non-nil %s", l, i, node))
		}
	}

	assert.Equal(t, true, 0, len(atree.litmaps[l]), fmt.Sprintf("Expected: levels[%d].litmap == 0, Actual: got %d", l, len(atree.litmaps[l])))

	atree.Finalize()

	for _, l := range []int{1, 7, 8, 10} {
		assert.Equal(t, true, minFixedChildren+1, len(atree.levels[l]), fmt.Sprintf("Expected: len(levels[%d]) == %d, Actual: got non-nil %s", l, minFixedChildren+1, len(atree.levels[l])))

		for i := 1; i < numAllTypes; i++ {
			node := atree.levels[l][i]
			assert.Nil(t, true, node, fmt.Sprintf("Expected: levels[%d][%d] == nil, Actual: got non-nil %s", l, i, node))
		}

		node := atree.levels[l][minFixedChildren]
		assert.Equal(t, true, TokenString, node.Type, fmt.Sprintf("Expected: levels[%d][%d].Type == TokenString, Actual: got %s", l, minFixedChildren+1, node.Type))
	}
}

func TestAnalyzerKeyValuePairs(t *testing.T) {
	atree := NewAnalyzer()
	msg := &message{}

	for _, data := range analyzerKeyValueSamples {
		msg.data = data
		err := msg.tokenize()
		assert.NoError(t, true, err)
		atree.Add(msg.tokens)
	}

	atree.Finalize()

	for _, i := range []int{0, 1, 3, 4, 8, 9, 11, 12, 14, 15, 17, 18, 20, 21, 23, 24, 26, 27, 29, 30, 32, 33, 35, 36, 38, 39, 42, 45, 47, 50, 53, 56, 59} {
		assert.Equal(t, true, 1, len(atree.litmaps[i]), fmt.Sprintf("Expected: levels[%d].litmap == 1, Actual: got %d", i, len(atree.litmaps[i])))
	}

	for _, i := range []int{41, 44} {
		assert.Equal(t, true, 2, len(atree.litmaps[i]), fmt.Sprintf("Expected: levels[%d].litmap == 2, Actual: got %d", i, len(atree.litmaps[i])))
	}

	for _, i := range []int{1, 4, 9, 12, 15, 18, 21, 24, 27, 30, 33, 36, 39, 42, 45} {
		_, ok := atree.litmaps[i]["="]
		assert.True(t, true, ok, fmt.Sprintf("Expected: levels[%d][\"=\"] exists, Actual: not exist", i))
	}

	_, ok := atree.litmaps[41]["duration"]
	assert.True(t, true, ok, fmt.Sprintf("Expected: levels[%d][\"duration\"] exists, Actual: not exist", 41))

	_, ok = atree.litmaps[41]["smac"]
	assert.True(t, true, ok, fmt.Sprintf("Expected: levels[%d][\"smac\"] exists, Actual: not exist", 41))

	if _, ok := atree.litmaps[44]["inpkt"]; !ok {
		t.Fatalf("Expected: levels[%d][\"inpkt\"] exists, Actual: not exist", 44)
	}

	if _, ok := atree.litmaps[44]["dmac"]; !ok {
		t.Fatalf("Expected: levels[%d][\"dmac\"] exists, Actual: not exist", 44)
	}
}

func TestAnalyzerMatchPatterns(t *testing.T) {
	atree := NewAnalyzer()
	msg := &message{}

	for _, data := range analyzerKeyValueSamples {
		msg.data = data
		err := msg.tokenize()
		assert.NoError(t, true, err)
		atree.Add(msg.tokens)
	}

	atree.Finalize()

	for i, data := range analyzerKeyValueSamples {
		msg.data = data
		err := msg.tokenize()
		assert.NoError(t, true, err)
		seq, err := atree.Analyze(msg.tokens)
		assert.Equal(t, true, analyzerKeyValuePatterns[i], seq.String())
	}

	for _, data := range analyzerSshdSamples {
		msg.data = data
		err := msg.tokenize()
		assert.NoError(t, true, err)
		atree.Add(msg.tokens)
	}

	atree.Finalize()

	for i, data := range analyzerSshdSamples {
		msg.data = data
		err := msg.tokenize()
		assert.NoError(t, true, err)
		seq, err := atree.Analyze(msg.tokens)
		assert.NoError(t, true, err)
		assert.Equal(t, true, analyzerSshdPatterns[i], seq.String())
	}
}
