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
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

var (
	ErrNegativeAdvance = errors.New("sequence: negative advance count")
	ErrAdvanceTooFar   = errors.New("sequence: advance count beyond input")
	ErrUnknownToken    = errors.New("sequence: unknown token encountered")
	ErrNoMatch         = errors.New("sequence: no pattern matched for this message")
)

type Scanner struct {
}

func NewScanner() *Scanner {
	return &Scanner{}
}

func (this Scanner) Scan(data string) (Sequence, error) {
	msg := &message{data: data}
	if err := msg.tokenize(); err != nil {
		return nil, err
	}

	return msg.tokens, nil
}

type message struct {
	data   string
	tokens Sequence

	state struct {
		// these are per token states
		tokenType TokenType
		tokenStop bool
		dots      int

		// these are per message states
		prevToken Token

		// single quote
		single bool

		// double quote
		double bool

		// angle bracket
		angle bool

		// cursor positions
		cur, start, end int

		// should the next token be a value?
		nextIsValue bool

		// how far from the = is the value, immediate following is 0
		valueDistance int
	}
}

func (this *message) tokenize() error {
	this.data = strings.TrimSpace(this.data)

	if len(this.data) == 0 {
		return fmt.Errorf("Zero length message")
	}

	// Reset the message states and start scanning for tokens
	this.reset()

	var err error

	for err = this.scan(); err == nil; err = this.scan() {
	}

	if err != nil && err != io.EOF {
		return err
	}

	return nil
}

func (this *message) scan() error {
	if this.state.start < this.state.end {
		// Number of spaces skipped
		nss := this.skipSpace(this.data[this.state.start:])
		this.state.start += nss

		l, t, err := this.scanToken(this.data[this.state.start:])
		if err != nil {
			return err
		} else if t == TokenUnknown {
			//return fmt.ErrUnknownToken
			return fmt.Errorf("unknown token encountered: %s\n%v", this.data[this.state.start:], t)
		}

		// remove any trailing spaces
		for this.data[this.state.start+l-1] == ' ' && l > 0 {
			l--
		}

		v := this.data[this.state.start : this.state.start+l]
		this.state.start += l

		token := Token{Type: t, Value: v, Field: FieldUnknown}

		switch {
		case v == "'":
			if this.state.single {
				this.state.single = false
			} else {
				this.state.single = true
			}

		case v == "\"":
			if this.state.double {
				this.state.double = false
			} else {
				this.state.double = true
			}

		case v == "<":
			this.state.angle = true

		case v == ">":
			this.state.angle = false

		case v[0] == '%' && v[len(v)-1] == '%':
			// this is a known TokenType or FieldType
			isTypeToken := false

			if f, ok := fieldTokenMap[v]; ok {
				token.Field = f.Field
				token.Type = f.Type
				isTypeToken = true
			} else if t2 := name2TokenType(v); t2 != TokenUnknown {
				token.Type = t2
				token.Field = FieldUnknown
				isTypeToken = true
			}

			if isTypeToken {
				this.tokens = append(this.tokens, token)
				this.state.prevToken = token
				return nil
			}
		}

		switch {
		case nss == 0 && v == "=":
			// This means we hit something like "abc=", so we assume abc, which is the
			// last token, is a key. It also means the next token should be a value
			if len(this.tokens) >= 1 {
				this.tokens[len(this.tokens)-1].IsKey = true
				this.state.nextIsValue = true
			}

		case nss == 0 && this.state.nextIsValue:
			if v == "'" || v == "\"" || v == "<" || v == ">" {
				// We hit something like ="def", so let's track how far away from the
				// = sign we will be.
				if this.state.valueDistance == 0 {
					this.state.valueDistance = 1
					this.state.nextIsValue = true
				} else {
					this.state.valueDistance = 0
					this.state.nextIsValue = false
				}
			} else {
				// This means we hit something like "=def", so if the token before the
				// "=" is a key, then this must be a value of the kv pair.
				keyDistance := 2 + this.state.valueDistance

				if len(this.tokens) >= keyDistance && this.tokens[len(this.tokens)-keyDistance].IsKey && !this.tokens[len(this.tokens)-keyDistance].IsValue {
					token.IsValue = true
					this.state.nextIsValue = false
					this.state.valueDistance = 0
					if token.Type == TokenLiteral {
						token.Type = TokenString
					}
				}
			}

		case nss == 0 && this.state.prevToken.Value == "=" && !this.state.nextIsValue:
			// If the previous token is "=" but this is not a value, then "=def" is
			// likely just a single token, then we merge it with the previous "="
			// token
			this.tokens[len(this.tokens)-1].Value += v
			this.state.prevToken = this.tokens[len(this.tokens)-1]
			this.state.nextIsValue = false
			this.state.valueDistance = 0
			return nil
		}

		this.tokens = append(this.tokens, token)
		this.state.prevToken = token

		return nil
	}

	return io.EOF
}

func (this *message) skipSpace(data string) int {
	// Skip leading spaces.
	i := 0

	for _, r := range data {
		if !unicode.IsSpace(r) {
			break
		} else {
			i++
		}
	}

	return i
}

func (this *message) scanToken(data string) (int, TokenType, error) {
	var (
		cur                        *timeNode = timeFsmRoot
		timeStop, macStop, macType bool
		timeLen, tokenLen          int
	)

	this.state.dots = 0
	this.state.tokenType = TokenUnknown
	this.state.tokenStop = false

	for i, r := range data {
		if !this.state.tokenStop {
			this.tokenStep(i, r)

			if !this.state.tokenStop {
				tokenLen++
			}
		}

		if !macStop {
			macType, macStop = this.macStep(i, r)

			if macType && macStop {
				return i + 1, TokenMac, nil
			}
		}

		if !timeStop {
			if cur = this.timeStep(r, cur); cur == nil {
				timeStop = true

				if timeLen > 0 {
					return timeLen, TokenTS, nil
				}
			} else if cur.final != TokenUnknown {
				if i+1 > timeLen {
					timeLen = i + 1
				}
			}
		}

		if this.state.tokenStop && timeStop && macStop {
			// If token length is 0, it means we didn't find time, nor did we find
			// a word, it cannot be space since we skipped all space. This means it
			// is a single character literal, so return that.
			if tokenLen == 0 {
				return 1, TokenLiteral, nil
			} else {
				return tokenLen, this.state.tokenType, nil
			}
		}
	}

	return len(data), this.state.tokenType, nil
}

func (this *message) timeStep(r rune, cur *timeNode) *timeNode {
	t := tnType(r)

	for _, n := range cur.children {
		if (n.ntype == timeNodeDigitOrSpace && (t == timeNodeDigit || t == timeNodeSpace)) ||
			(n.ntype == t && (t != timeNodeLiteral || (t == timeNodeLiteral && rune(n.value) == r))) {

			return n
		}
	}

	return nil
}

func (this *message) tokenStep(index int, r rune) {
	switch {
	case this.state.tokenType == TokenURL:
		if (index == 1 && (r == 't' || r == 'T')) ||
			(index == 2 && (r == 't' || r == 'T')) ||
			(index == 3 && (r == 'p' || r == 'P')) ||
			(index == 4 && (r == 's' || r == 'S')) ||
			((index == 4 || index == 5) && r == ':') ||
			((index == 5 || index == 6) && r == '/') ||
			((index == 6 || index == 7) && r == '/') ||
			(index >= 6 && !unicode.IsSpace(r)) {

			this.state.tokenType = TokenURL
		} else if unicode.IsSpace(r) {
			this.state.tokenStop = true
		} else {
			this.state.tokenType = TokenLiteral
		}

	case index == 0 && (r == 'h' || r == 'H'):
		this.state.tokenType = TokenURL

	case (r >= 'a' && r <= 'z') || r == '-' || r == '_' || r == '/' || r == '\\' || r == '%' || r == '*' || r == '@' || r == '$' || (r >= 'a' && r <= 'Z'):
		if r == '/' || r == ':' {
			if this.state.tokenType == TokenIPv4 {
				this.state.tokenStop = true
			} else if this.state.prevToken.Type == TokenIPv4 {
				this.state.tokenType = TokenLiteral
				this.state.tokenStop = true
			} else {
				this.state.tokenType = TokenLiteral
			}
		} else {
			this.state.tokenType = TokenLiteral
		}

	case r >= '0' && r <= '9':
		if this.state.tokenType == TokenInteger || index == 0 {
			this.state.tokenType = TokenInteger
		} else if this.state.tokenType == TokenIPv4 && this.state.dots < 4 {
			this.state.tokenType = TokenIPv4
		} else if this.state.tokenType == TokenFloat && this.state.dots == 1 {
			this.state.tokenType = TokenFloat
		} else {
			this.state.tokenType = TokenLiteral
		}

	case r == '.':
		this.state.dots++

		if this.state.tokenType == TokenInteger && this.state.dots == 1 {
			this.state.tokenType = TokenFloat
		} else if (this.state.dots > 1 && this.state.tokenType == TokenFloat) ||
			(this.state.dots < 4 && this.state.tokenType == TokenIPv4) {

			this.state.tokenType = TokenIPv4
		} else {
			this.state.tokenType = TokenLiteral
		}

	case r == '\'':
		if index == 0 && this.state.single == false {
			//this.state.single = true
			this.state.tokenStop = true
		} else if index != 0 && this.state.single == true {
			this.state.tokenStop = true
		} else if index == 0 && this.state.single == true {
			//this.state.single = false
			this.state.tokenStop = true
		} else {
			this.state.tokenType = TokenLiteral
		}

	default:
		if !this.state.single {
			this.state.tokenStop = true
		}
	}

	//fmt.Printf("%c: tokenStop = %t, tokenType = %s, dots = %d\n", r, tokenStop, TokenNames[tokenType], dots)
	if this.state.tokenStop {
		if (this.state.tokenType == TokenIPv4 && this.state.dots != 3) ||
			(this.state.tokenType == TokenFloat && this.state.dots != 1) {

			this.state.tokenType = TokenLiteral
		}
	}
}

// Returns bool, bool, first one is true if the it's a mac type, second is whether to stop scanning
func (this *message) macStep(index int, r rune) (bool, bool) {
	switch {
	case index == 0 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, false

	case index == 1 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, false

	case index == 2 && r == ':':
		return true, false

	case index == 3 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, false

	case index == 4 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, false

	case index == 5 && r == ':':
		return true, false

	case index == 6 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, false

	case index == 7 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, false

	case index == 8 && r == ':':
		return true, false

	case index == 9 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, false

	case index == 10 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, false

	case index == 11 && r == ':':
		return true, false

	case index == 12 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, false

	case index == 13 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, false

	case index == 14 && r == ':':
		return true, false

	case index == 15 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, false

	case index == 16 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, true
	}

	return false, true
}

func (this *message) reset() {
	this.tokens = make(Sequence, 0, 20)
	this.state.tokenType = TokenUnknown
	this.state.tokenStop = false
	this.state.dots = 0
	this.state.prevToken = Token{}
	this.state.single = false
	this.state.start = 0
	this.state.end = len(this.data)
	this.state.cur = 0
	this.data = strings.ToLower(this.data)
}
