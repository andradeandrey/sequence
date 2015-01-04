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

type Analyzer struct {
	root *analyzerNode
	leaf *analyzerNode

	levels    [][]*analyzerNode
	litmaps   []map[string]int
	nodeCount []int

	mu sync.RWMutex
}

type analyzerNode struct {
	Token

	index int
	level int

	isKey   bool
	isValue bool

	leafNode bool

	parents  *bitset.BitSet
	children *bitset.BitSet
}

type stackAnalyzerNode struct {
	node  *analyzerNode
	level int
	score int
}

func (this *stackAnalyzerNode) String() string {
	return fmt.Sprintf("level=%d, score=%d, token=%v, leaf=%t", this.level, this.score, this.node.Token, this.node.leafNode)
}

func NewAnalyzer() *Analyzer {
	tree := &Analyzer{
		root: newAnalyzerNode(),
		leaf: newAnalyzerNode(),
	}

	tree.root.level = -1

	return tree
}

func newAnalyzerNode() *analyzerNode {
	return &analyzerNode{
		parents:  bitset.New(1),
		children: bitset.New(1),
	}
}

func (this *analyzerNode) String() string {
	return fmt.Sprintf("%d/%d: %s %t %t %t\n--%s\n--%s\n", this.level, this.index, this.Token.String(),
		this.isKey, this.isValue, this.leafNode, this.parents.DumpAsBits(), this.children.DumpAsBits())
}

func (this *Analyzer) Analyze(seq Sequence) (Sequence, error) {
	this.mu.RLock()
	defer this.mu.RUnlock()

	path, err := this.analyzeMessage(seq)
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

func (this *Analyzer) Add(seq Sequence) error {
	this.mu.Lock()
	defer this.mu.Unlock()

	// Add enough levels to support the depth of the token list
	if l := len(seq) + 1 - len(this.levels); l > 0 {
		newlevels := make([][]*analyzerNode, l)
		// the maps are used to hash literals to see if they exist
		newmaps := make([]map[string]int, l)

		for i := 0; i < l; i++ {
			newlevels[i] = make([]*analyzerNode, minFixedChildren)
			newlevels[i][0] = this.leaf
			newmaps[i] = make(map[string]int)
		}

		this.levels = append(this.levels, newlevels...)
		this.litmaps = append(this.litmaps, newmaps...)
	}

	var (
		parent, foundNode *analyzerNode = this.root, nil
	)

	for i, token := range seq {
		foundNode = nil

		switch {
		case token.Field != FieldUnknown:
			// if Field is not FieldUnknown, it means the Field is one of the recognized
			// field type. In this case, we just add it to the list of field types.

			if foundNode = this.levels[i][int(token.Field)]; foundNode == nil {
				foundNode = newAnalyzerNode()
				foundNode.Token = token
				foundNode.level = i
				foundNode.index = int(token.Field)
				this.levels[i][foundNode.index] = foundNode
			}

		case token.Type != TokenUnknown && token.Type != TokenLiteral:
			// If this is a known token type but it's not a literal, it means this
			// token could contain different values. In this case, we add it to the
			// list of token types.

			if foundNode = this.levels[i][numFieldTypes+int(token.Type)]; foundNode == nil {
				foundNode = newAnalyzerNode()
				foundNode.Token = token
				foundNode.level = i
				foundNode.index = numFieldTypes + int(token.Type)
				this.levels[i][foundNode.index] = foundNode
			}

		case token.Field == FieldUnknown && token.Type == TokenLiteral:
			// if the field type is unknown, and the token type is literal, that
			// means this is some type of string we parsed from the message.

			// If we have gotten here, it means we found a string that we cannot
			// determine if it's a fixed literal, or a changing variable. So we have
			// to keep this in the literal map to track it.
			// If we have seen this literal before, then there's already a node
			if j, ok := this.litmaps[i][token.Value]; ok {
				foundNode = this.levels[i][j]
			} else {
				// Otherwise we create a new node for this first time literal,
				// add it to the end of the nodes for this level, and keep track
				// of the index in the slice/list in the literal map so we can
				// quick it find its location later.
				foundNode = newAnalyzerNode()
				this.levels[i] = append(this.levels[i], foundNode)
				foundNode.Token = token
				foundNode.level = i
				foundNode.index = len(this.levels[i]) - 1
				foundNode.Field = FieldUnknown
				this.litmaps[i][foundNode.Value] = foundNode.index
				foundNode.isKey = token.IsKey
			}
		}

		// We use a bitset to track parent and child relationships. In this case,
		// we set the parent bit for the index of the current node, and set the
		// child bit for the index of the parent node.
		if parent != nil {
			foundNode.parents.Set(uint(parent.index))
			parent.children.Set(uint(foundNode.index))
		}

		parent = foundNode
	}

	// If we are finished with all the tokens, then the current parent node is the
	// last node we created, which means it's a leaf node.
	parent.leafNode = true

	// We set the 0th bit of the children bitset ...
	parent.children.Set(0)

	return nil
}

// finalize has 2 phases
// 1. merge all the nodes that share at least 1 parent and 1 child
// 2. compact the trees and remove all dead nodes
func (this *Analyzer) Finalize() error {
	this.mu.Lock()
	defer this.mu.Unlock()

	//fmt.Printf("in finalize\n")
	if err := this.merge(); err != nil {
		return err
	}

	return this.compact()
}

// merge merges trie[i][k] into trie[i][j] and updates all parents and children
// appropriately
func (this *Analyzer) merge() error {
	// For every level of this tree ...
	for i, level := range this.levels {
		// And for every child of this level ...
		for j := minFixedChildren; j < len(level); j++ {
			cur := level[j]

			// - If the node is nil, then most likely it's been merged, so let's move on.
			// - If the node is a key (isKey == true), then it's a literal that shouldn't
			//   be merged, so let's move on.
			// - If the node is a single character literal, then it shouldn't be merged,
			//   so let's move on.
			if cur == nil || (cur.Type == TokenLiteral && len(cur.Value) == 1) || cur.isKey {
				continue
			}

			// Finds the nodes that share at least 1 parent and 1 child with trie[i][j]
			// These will be the nodes that get merged into j
			mergeSet, err := this.getMergeSet(i, j, cur)
			if err != nil {
				return err
			}

			// if the number of nodes share at least 1 parent and 1 child is only 1, then
			// it means it's only the curernt node left. In other words, no other nodes share
			// at least 1 parent and 1 child with the current node. If so, move on.
			if mergeSet.Count() > 1 {
				// Otherwise, we want to merge the nodes that are in the mergeSet

				// parents is the new parent bitset after the merging of all relevant nodes
				parents := cur.parents

				// children is the new children bitset after merging all relevant nodes
				children := cur.children

				leafNode := cur.leafNode

				// For every node aside from the current node, let's merge their info
				// into the current node (cur)
				//
				// Check to see if the kth bit is set, if so, then we merge the kth node
				// into current node

				for k, e := mergeSet.NextSet(uint(j) + 1); e; k, e = mergeSet.NextSet(uint(k) + 1) {

					// The parents of the final merged node is the combination of all
					// parents from all the merge nodes
					parents.InPlaceUnion(level[k].parents)

					// The children of the final merged node is the combination of all
					// children from all the merge nodes
					children.InPlaceUnion(level[k].children)

					if leafNode || level[k].leafNode {
						leafNode = true
					}

					// Once we merge the parent and children bitset, we need to make sure
					// all the parents of the merged node no longer points to the merged
					// node, so we go through each parent and clear the kth child bit
					//
					// Make sure we are not at the top level since there's no more levels
					// above it
					if i > 0 {
						plen := int(level[k].parents.Len())

						for l := 0; l < plen; l++ {
							// For each of the set parent bit of the kth node, we clear
							// the kth child bit in the parent's children bitset
							//
							// Also, we set the parent's jth child bit since the parent
							// needs to point to the new merged node
							if level[k].parents.Test(uint(l)) {
								this.levels[i-1][l].children.Clear(uint(k))
								this.levels[i-1][l].children.Set(uint(j))
							}
						}
					}

					// Same for all the children of the merged node. For each of the
					// children, we clear the kth parent bit
					//
					// Make sure we are not at the bottom level since there's no more
					// levels below
					if i < len(this.levels)-1 {
						for l := 0; l < int(level[k].children.Len()); l++ {
							// For each of the set child bit of the kth node, we clear
							// the kth parent bit in the child's parents bitset
							//
							// Also, we set the child's jth parent bit since the parent
							// needs to point to the new merged node
							if level[k].children.Test(uint(l)) {
								this.levels[i+1][l].parents.Clear(uint(k))
								this.levels[i+1][l].parents.Set(uint(j))
							}
						}
					}

					level[k] = nil
				}

				cur.parents = parents
				cur.children = children
				cur.leafNode = leafNode
				cur.Type = TokenString
			}
		}
	}

	return nil
}

// getMergeSet finds the nodes that share at least 1 parent and 1 child with trie[i][j]
// These will be the nodes that get merged into j
func (this *Analyzer) getMergeSet(i, j int, cur *analyzerNode) (*bitset.BitSet, error) {
	level := this.levels[i]

	// shareParents is a bitset marks all the nodes that share at least 1 parent
	// with the current node being checked
	shareParents := bitset.New(uint(len(level)))

	// shareChildren is a bitset marks all the nodes that share at least 1 child
	// with the current node being checked
	shareChildren := bitset.New(uint(len(level)))

	// Set the current node's bit in both shareParents and shareChildren
	shareParents.Set(uint(j))
	shareChildren.Set(uint(j))

	// For each node after the current constant/word node, check to see if there's
	// any that share at least 1 parent or 1 child
	for k, tmp := range level[j+1:] {
		// - If node if nil, then most likely have been merged, let's move on
		// - We only merge nodes that are literals or strings, anything else
		//   is already a variable so move on
		// - If node is a single character literal, then not merging, move on
		if tmp == nil ||
			(tmp.Type != TokenLiteral && tmp.Type != TokenString) ||
			(tmp.Type == TokenLiteral && len(tmp.Value) == 1) {

			continue
		}

		// Take the intersection of current node's parent bitset and the next
		// constant/word node's parent bitset, if the cardinality of the result
		// bitset is greater than 0, then it means they share at least 1 parent.
		// If so, then set the bit that represent that node in shareParent.
		if c := cur.parents.IntersectionCardinality(tmp.parents); c > 0 {
			shareParents.Set(uint(k + j + 1))
		}

		// Take the intersection of current node's children bitset and the next
		// constant/word node's children bitset, if the cardinality of the result
		// bitset is greater than 0, then it means they share at least 1 child.
		// If so, then set the bit that represent that node in shareChildren.
		if c := cur.children.IntersectionCardinality(tmp.children); c > 0 {
			shareChildren.Set(uint(k + j + 1))
		}
	}

	// The goal is to identify all nodes that share at least 1 parent and 1 child
	// with the current node. Now that we have all the nodes that share at least
	// 1 parent in shareParents, and all the nodes that share at least 1 child
	// in shareChildren, we can then take the intersection of shareParent and
	// shareChildren to get all the nodes that share both
	mergeSet := shareParents.Intersection(shareChildren)

	return mergeSet, nil
}

func (this *Analyzer) compact() error {
	// Build a complete new trie
	newLevels := make([][]*analyzerNode, len(this.levels))

	// Each level has a hash map of literals that points to the literal's
	// index position in the level slice
	newmaps := make([]map[string]int, len(this.litmaps))
	for i := 0; i < len(newmaps); i++ {
		newmaps[i] = make(map[string]int)
	}

	this.nodeCount = make([]int, len(this.levels))

	// Copy all the fixed children (leaf, TokenNames, FieldTokenMap) into the slice
	// Copy any non-nil children into the slice
	// Fix the index for all the children
	// Add any literals to the hash
	for i, level := range this.levels {
		for j, cur := range level {
			if j < minFixedChildren || cur != nil {
				newLevels[i] = append(newLevels[i], cur)

				if cur != nil {
					this.nodeCount[i]++
					cur.index = len(newLevels[i]) - 1

					if cur.Type == TokenLiteral {
						newmaps[i][cur.Value] = cur.index
					}
				}
			}
		}

	}

	// Reset all the parents and children relationship for each node
	for i, level := range newLevels {
		for _, cur := range level {
			if cur == nil {
				continue
			}

			newParents := bitset.New(1)

			if i > 0 {
				for k, e := cur.parents.NextSet(0); e; k, e = cur.parents.NextSet(k + 1) {
					// recall that index is already set to the index of the newLevels
					newParents.Set(uint(this.levels[i-1][k].index))
				}
			} else {
				newParents.Set(0)
			}

			newChildren := bitset.New(1)

			if i < len(newLevels)-1 {
				for k, e := cur.children.NextSet(0); e; k, e = cur.children.NextSet(k + 1) {
					newChildren.Set(uint(this.levels[i+1][k].index))
				}
			}

			cur.parents = newParents
			cur.children = newChildren

			if cur.Type != TokenLiteral {
				cur.Value = ""
			}
		}
	}

	this.levels = newLevels
	this.litmaps = newmaps

	return nil
}

func (this *Analyzer) analyzeMessage(seq Sequence) ([]*analyzerNode, error) {
	var (
		cur stackAnalyzerNode

		// Keep track of the path we have walked
		// +1 because the first level is the root node, so the actual path is going
		// to be level 1 .. n. When we return the actual path we will get rid of the
		// first element in the slice.
		path []*analyzerNode = make([]*analyzerNode, len(seq)+1)

		// Keeps track of ALL paths of the matched patterns
		paths [][]*analyzerNode

		bestScore int
		bestPath  int
	)

	// toVisit is a stack, nodes that need to be visited are appended to the end,
	// and we take nodes from the end to visit
	toVisit := append(make([]stackAnalyzerNode, 0, 100), stackAnalyzerNode{this.root, 0, 0})

	// Depth-first analysis of the message using the current tree
	for len(toVisit) > 0 {
		// Take the last node from the stack to visit
		cur = toVisit[len(toVisit)-1]

		//glog.Debugf("cur=%s, len(path)=%d", cur.String(), len(path))

		// Delete the last node from the stack
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
				tmppath := append(make([]*analyzerNode, 0, len(path)-1), path[1:]...)
				paths = append(paths, tmppath)

				if cur.score > bestScore {
					bestScore = cur.score
					bestPath = len(paths) - 1
				}
			}

			continue
		}

		token := seq[cur.level]

		// For each of the child for the current node, we test to see if they should
		// be added to the stack for visiting.
		for i, e := cur.node.children.NextSet(0); e; i, e = cur.node.children.NextSet(i + 1) {
			node := this.levels[cur.node.level+1][i]

			if node != nil {
				// Anything other than these 3 conditions are considered no match.
				switch {
				case node.Type == token.Type && token.Type != TokenLiteral && token.Type != TokenString:
					// If the child node and the msg token have the same type, and
					// type is not a literal or a string, that means we have a match
					// for this level, so let's add it to the stack to visit.
					//
					// This is also considered a full match since the types matched
					toVisit = append(toVisit, stackAnalyzerNode{node, cur.level + 1, cur.score + fullMatchWeight})

				case node.Type == TokenString && token.Type == TokenLiteral &&
					(len(token.Value) != 1 || (len(token.Value) == 1 && unicode.IsLetter(rune(token.Value[0])))):
					// If the node is a string and token is a non-one-character literal,
					// then it's considered a partial match, since a literal is
					// technically a string.
					toVisit = append(toVisit, stackAnalyzerNode{node, cur.level + 1, cur.score + partialMatchWeight})

				case node.Type == TokenLiteral && token.Type == TokenLiteral && node.Value == token.Value:
					// If the parse node and token are both literal type, then the
					// value must also match. If matched, then let's add to the stack
					// for visiting.
					//
					// Because the literal value matched, this is also considered to
					// be a full match.
					toVisit = append(toVisit, stackAnalyzerNode{node, cur.level + 1, cur.score + fullMatchWeight})

				case token.Type == TokenString && token.IsValue:
					toVisit = append(toVisit, stackAnalyzerNode{node, cur.level + 1, cur.score + fullMatchWeight})
				}
			}
		}
	}

	if len(paths) > bestPath {
		//return paths[bestPath], maxs[bestPath], nil
		return paths[bestPath], nil
	}

	return nil, ErrNoMatch
}

func (this *Analyzer) dump() int {
	total := 0
	for i, l := range this.levels {
		fmt.Printf("level %d (%d children):\n", i, len(l))
		total += len(l)

		for j, n := range l {
			if n != nil {
				fmt.Printf("node %d.%d: %s %s - %s\n", i, j, n.Type, n.Field, n)
			}
		}
	}

	return total
}
