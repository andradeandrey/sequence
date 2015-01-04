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

import "bytes"

var TimeFormats []string = []string{
	"Mon Jan _2 15:04:05 2006",
	"Mon Jan _2 15:04:05 MST 2006",
	"Mon Jan 02 15:04:05 -0700 2006",
	"02 Jan 06 15:04 MST",
	"02 Jan 06 15:04 -0700",
	"Monday, 02-Jan-06 15:04:05 MST",
	"Mon, 02 Jan 2006 15:04:05 MST",
	"Mon, 02 Jan 2006 15:04:05 -0700",
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02T15:04:05.999999999Z07:00",
	"Jan _2 15:04:05",
	"Jan _2 15:04:05.000",
	"Jan _2 15:04:05.000000",
	"Jan _2 15:04:05.000000000",
	"_2/Jan/2006:15:04:05 -0700",
	"Jan 2, 2006 3:04:05 PM",
	"Jan 2 2006 15:04:05",
	"Jan 2 15:04:05 2006",
	"Jan 2 15:04:05 -0700",
	"2006-01-02 15:04:05,000 -0700",
	"2006-01-02 15:04:05 -0700",
	"2006-01-02 15:04:05-0700",
	"2006-01-02 15:04:05,000",
	"2006-01-02 15:04:05",
	"2006/01/02 15:04:05",
	"06-01-02 15:04:05,000 -0700",
	"06-01-02 15:04:05,000",
	"06-01-02 15:04:05",
	"06/01/02 15:04:05",
	"15:04:05,000",
	"1/2/2006 3:04:05 PM",
	"1/2/06 3:04:05.000 PM",
	"1/2/2006 15:04",
}

type timeNodeType int

type timeNode struct {
	ntype    timeNodeType
	value    byte
	final    TokenType
	subtype  int
	children []*timeNode
}

const (
	timeNodeRoot timeNodeType = iota
	timeNodeLeaf
	timeNodeDigit
	timeNodeLetter
	timeNodeLiteral
	timeNodeSpace
	timeNodeDigitOrSpace
	timeNodePlusOrMinus
)

var (
	timeFsmRoot *timeNode
)

func init() {
	timeFsmRoot = buildTimeFSM()
}

func buildTimeFSM() *timeNode {
	root := &timeNode{ntype: timeNodeRoot}

	for i, f := range TimeFormats {
		buf := bytes.ToLower([]byte(f))
		parent := root

		for _, b := range buf {
			t := tnType(rune(b))

			hasChild := false
			var child *timeNode

			for _, child = range parent.children {
				if (child.ntype == t && (t != timeNodeLiteral || (t == timeNodeLiteral && child.value == b))) ||
					(child.ntype == timeNodeDigitOrSpace && (t == timeNodeDigit || t == timeNodeSpace)) {
					hasChild = true
					break
				} else if child.ntype == timeNodeDigit && t == timeNodeDigitOrSpace {
					child.ntype = timeNodeDigitOrSpace
					hasChild = true
					break
				}
			}

			if hasChild == false {
				child = &timeNode{ntype: t, value: b}
				parent.children = append(parent.children, child)
			}

			parent = child
		}

		parent.final = TokenTS
		parent.subtype = i
	}

	return root
}

func tnType(r rune) timeNodeType {
	switch {
	case r >= '0' && r <= '9':
		return timeNodeDigit
	case r >= 'a' && r <= 'z':
		return timeNodeLetter
	case r == ' ':
		return timeNodeSpace
	case r == '_':
		return timeNodeDigitOrSpace
	case r == '+' || r == '-':
		return timeNodePlusOrMinus
	case r >= 'A' && r <= 'Z':
		return timeNodeLetter
	}

	return timeNodeLiteral
}
