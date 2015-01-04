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

	"github.com/willf/bitset"
)

type Parser struct {
	root   *parseNode
	height int
	mu     sync.RWMutex
}

type parseNode struct {
	Token

	leafNode        bool
	fixedChildren   []*parseNode
	fixedSet        *bitset.BitSet
	literalChildren map[string]*parseNode
}

type stackParseNode struct {
	node  *parseNode
	level int
	score int
}

func (this *stackParseNode) String() string {
	return fmt.Sprintf("level=%d, score=%d, %s", this.level, this.score, this.node)
}

func NewParser() *Parser {
	return &Parser{
		root:   newParseNode(),
		height: 0,
	}
}

func newParseNode() *parseNode {
	return &parseNode{
		leafNode:        false,
		fixedChildren:   make([]*parseNode, numAllTypes),
		fixedSet:        bitset.New(uint(numAllTypes)),
		literalChildren: make(map[string]*parseNode),
	}
}

func (this *parseNode) String() string {
	return fmt.Sprintf("leaf=%t, node=%s", this.leafNode, this.Token.String())
}

func (this *Parser) Add(seq Sequence) error {
	this.mu.Lock()
	defer this.mu.Unlock()

	found := (*parseNode)(nil)
	cur := this.root
	var ok bool

	for _, token := range seq {
		if token.Field != FieldUnknown {
			found = cur.fixedChildren[token.Field]
			if found == nil {
				found = newParseNode()
				found.Token = token
				cur.fixedChildren[token.Field] = found
				cur.fixedSet.Set(uint(token.Field))
			}
		} else if token.Type != TokenUnknown && token.Type != TokenLiteral {
			found = cur.fixedChildren[numFieldTypes+int(token.Type)]
			if found == nil {
				found = newParseNode()
				found.Token = token
				cur.fixedChildren[numFieldTypes+int(token.Type)] = found
				cur.fixedSet.Set(uint(numFieldTypes) + uint(token.Type))
			}
		} else if token.Type == TokenLiteral {
			found, ok = cur.literalChildren[token.Value]
			if !ok {
				found = newParseNode()
				found.Token = token
				cur.literalChildren[token.Value] = found
			}
		}

		//glog.Debugf("found=%s", found.String())

		cur = found
	}

	cur.leafNode = true

	//fmt.Printf("parser.go/AddPattern(): count = %d, height = %d\n", msg.Count(), this.height)
	if len(seq) > this.height {
		this.height = len(seq)
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

	var seq2 Sequence

	for i, n := range path {
		n.Token.Value, n.Token.IsKey, n.Token.IsValue = seq[i].Value, seq[i].IsKey, seq[i].IsValue
		seq2 = append(seq2, n.Token)
	}

	return seq2, nil
}

func (this *Parser) parseMessage(seq Sequence) ([]*parseNode, error) {
	var (
		cur stackParseNode

		// Keep track of the path we have walked
		path []*parseNode = make([]*parseNode, len(seq)+1)

		// Keeps track of ALL paths of the matched patterns
		paths [][]*parseNode

		bestScore int
		bestPath  int
	)

	// toVisit is a stack, nodes that need to be visited are appended to the end,
	// and we take nodes from the end to visit
	toVisit := append(make([]stackParseNode, 0, 100), stackParseNode{this.root, 0, 0})

	for len(toVisit) > 0 {
		cur = toVisit[len(toVisit)-1]
		//glog.Debugf("cur=%s", cur.String())

		toVisit = toVisit[:len(toVisit)-1]

		if cur.level <= len(path) {
			// If we are here, then the current level is less than the number of tokens,
			// then we can assume this is still a possible path. So let's track it.
			path[cur.level] = cur.node
		}

		// If the current level we are visiting is greater or equal to the number of
		// tokens in the message, that means we have exhausted the message length. If
		// the current node is also a leaf node, it means we have matched a pattern,
		// so let's calculate the scores and max depth of this path, save the depth,
		// score and path, and then move on to the next possible path.
		if cur.level >= len(seq) {
			// If this is a leaf node, that means we are at the end of the tree, and
			// since this is also the last token, it means we have a match. If it's
			// not a leaf node, it means we do not have a match.
			if cur.node.leafNode {
				tmppath := append(make([]*parseNode, 0, len(path)-1), path[1:]...)
				paths = append(paths, tmppath)

				if cur.score > bestScore {
					bestScore = cur.score
					bestPath = len(paths) - 1
				}
			}

			continue
		}

		token := seq[cur.level]

		//glog.Debugf("token=%q", token)

		for i, e := cur.node.fixedSet.NextSet(0); e; i, e = cur.node.fixedSet.NextSet(i + 1) {
			node := cur.node.fixedChildren[i]
			if node != nil {
				switch {
				case node.Type == token.Type:
					toVisit = append(toVisit, stackParseNode{node, cur.level + 1, cur.score + fullMatchWeight})

				case node.Type == TokenString && token.Type == TokenLiteral &&
					(len(token.Value) != 1 || (len(token.Value) == 1 && unicode.IsLetter(rune(token.Value[0])))):
					toVisit = append(toVisit, stackParseNode{node, cur.level + 1, cur.score + partialMatchWeight})
				}
			}
		}

		if token.Type == TokenLiteral {
			//glog.Debugf("%v", cur.node.literalChildren)
			//glog.Debugf("%q", token.Value)
			if node, ok := cur.node.literalChildren[token.Value]; ok {
				//glog.Debugf("found literal ok")
				toVisit = append(toVisit, stackParseNode{node, cur.level + 1, cur.score + 2})
			}
		}
	}

	if len(paths) > bestPath {
		return paths[bestPath], nil
	}

	return nil, ErrNoMatch
}

func (this *Parser) dump() {
	toVisit := append(make([]*stackParseNode, 0, 100), &stackParseNode{this.root, -1, 0})

	for len(toVisit) > 0 {
		cur := toVisit[len(toVisit)-1]
		toVisit = toVisit[:len(toVisit)-1]

		for _, node := range cur.node.fixedChildren {
			if node == nil {
				continue
			}

			toVisit = append(toVisit, &stackParseNode{node, cur.level + 1, 0})
		}

		for _, node := range cur.node.literalChildren {
			toVisit = append(toVisit, &stackParseNode{node, cur.level + 1, 0})
		}

		for i := 0; i < cur.level+1; i++ {
			fmt.Printf("__")
		}

		fmt.Println(cur.node)
	}
}
