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
	"sync"
	"unicode"
)

type Parser struct {
	root   *parseNode
	height int
	mu     sync.RWMutex
}

type parseNode struct {
	Token

	leaf     bool
	children map[string]*parseNode
}

type stackParseNode struct {
	node  *parseNode
	level int // current level of the node
	score int // the score of the path traversed
	next  int // the next token of the sequence to consume
}

func (this stackParseNode) String() string {
	return fmt.Sprintf("level=%d, score=%d, next=%d, %s", this.level, this.score, this.next, this.node)
}

func NewParser() *Parser {
	return &Parser{
		root:   newParseNode(),
		height: 0,
	}
}

func newParseNode() *parseNode {
	return &parseNode{
		children: make(map[string]*parseNode),
	}
}

func (this *parseNode) String() string {
	return fmt.Sprintf("leaf=%t, node=%s, children=%d", this.leaf, this.Token.String(), len(this.children))
}

func (this *Parser) Add(seq Sequence) error {
	this.mu.Lock()
	defer this.mu.Unlock()

	cur := this.root

	for _, token := range seq {
		var key string

		switch {
		case token.Field != FieldUnknown:
			key = token.Field.String()

		case token.Type != TokenUnknown && token.Type != TokenLiteral:
			key = token.Type.String()

		case token.Type == TokenLiteral:
			key = token.Value
		}

		found, ok := cur.children[key]
		if !ok {
			found = newParseNode()
			found.Token = token
			cur.children[key] = found
		}

		cur = found
	}

	cur.leaf = true

	//fmt.Printf("parser.go/AddPattern(): count = %d, height = %d\n", msg.Count(), this.height)
	if len(seq)+1 > this.height {
		this.height = len(seq) + 1
	}

	return nil
}

func (this *Parser) Parse(seq Sequence) (Sequence, error) {
	this.mu.RLock()
	defer this.mu.RUnlock()

	path, err := this.parseMessage(seq)
	if err != nil {
		return nil, err
	}

	seq2 := make(Sequence, 0, len(path))

	for i, n := range path {
		n.Token.Value, n.Token.IsKey, n.Token.IsValue = seq[i].Value, seq[i].IsKey, seq[i].IsValue
		seq2 = append(seq2, n.Token)
	}

	return seq2, nil
}

func (this *Parser) parseMessage(seq Sequence) ([]parseNode, error) {
	var (
		cur stackParseNode

		// Keep track of the path we have walked
		path []parseNode = make([]parseNode, len(seq)+1)

		// Keeps track of ALL paths of the matched patterns
		paths [][]parseNode

		bestScore int
		bestPath  int
	)

	if len(seq) == 0 {
		return nil, ErrNoMatch
	}

	//glog.Debugf("%s", seq.LongString())
	// toVisit is a stack, children that need to be visited are appended to the end,
	// and we take children from the end to visit
	toVisit := make([]stackParseNode, 0, 10)
	this.addNodesToVisit(&toVisit, stackParseNode{node: this.root}, seq[0])

	for len(toVisit) > 0 {
		// pop the last element from the toVisit stack
		toVisit, cur = toVisit[:len(toVisit)-1], toVisit[len(toVisit)-1]

		//glog.Debugf("cur=%s", cur.String())

		var token Token
		var next int

		if cur.node.Token.Range == 0 || cur.node.Token.Range == 1 {
			token = seq[cur.next]
			token.Range = 1
			next = cur.next + 1
		} else {
			token.Field = cur.node.Token.Field
			token.Type = TokenString
			token.Range = 0

			for next = cur.next; next < len(seq) && next < cur.next+cur.node.Token.Range; next++ {
				token.Value += " " + seq[next].Value
				token.Range++
			}
		}

		//glog.Debugf("token=%s", token)

		switch {
		case cur.node.Type == token.Type && token.Type != TokenLiteral:
			cur.score += fullMatchWeight

		case cur.node.Type == TokenString && token.Type == TokenLiteral &&
			(len(token.Value) != 1 || (len(token.Value) == 1 && unicode.IsLetter(rune(token.Value[0])))):
			cur.score += partialMatchWeight

		case token.Type == TokenLiteral && token.Value == cur.node.Value:
			cur.score += fullMatchWeight

		default:
			continue
		}

		path[cur.level].Token = cur.node.Token
		path[cur.level].Token.Value = token.Value
		path[cur.level].Token.Range = cur.node.Range
		cur.next = next

		if next >= len(seq) {
			if cur.node.leaf {
				//glog.Debugf("Found path")
				newpath := append(make([]parseNode, 0, cur.level+1), path[1:cur.level+1]...)
				paths = append(paths, newpath)

				if cur.score > bestScore {
					bestScore = cur.score
					bestPath = len(paths) - 1
				}
			}

			continue
		}

		//toVisit = append(toVisit, this.nodesToVisit(cur, seq[next])...)
		this.addNodesToVisit(&toVisit, cur, seq[next])
	}

	if len(paths) > bestPath {
		return paths[bestPath], nil
	}

	return nil, ErrNoMatch
}

func (this *Parser) addNodesToVisit(toVisit *[]stackParseNode, cur stackParseNode, next Token) {
	for _, node := range cur.node.children {
		if (node.Type == next.Type && next.Type != TokenLiteral) ||
			(node.Type == TokenString && next.Type == TokenLiteral) ||
			(next.Type == TokenLiteral && node.Value == next.Value) {

			//glog.Debugf("Adding: %s", node)
			*toVisit = append(*toVisit, stackParseNode{node, cur.level + 1, cur.score, cur.next})
		}
	}
}
