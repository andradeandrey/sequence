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
	"strconv"
	"strings"
	"unicode"
)

var (
	ErrNegativeAdvance = errors.New("sequence: negative advance count")
	ErrAdvanceTooFar   = errors.New("sequence: advance count beyond input")
	ErrUnknownToken    = errors.New("sequence: unknown token encountered")
	ErrNoMatch         = errors.New("sequence: no pattern matched for this message")
	ErrInvalidCount    = errors.New("sequence: invalid count for field token")
)

// Scanner is a sequential lexical analyzer that breaks a log message into a sequence
// of tokens. It is sequential because it goes through log message sequentially
// tokentizing each part of the message, without the use of regular expressions.
// The scanner currently recognizes time stamps, IPv4 addresses, URLs, MAC addresses,
// integers and floating point numbers. It also recgonizes key=value or key="value"
// or key='value' or key=<value> pairs.
type Scanner struct {
}

func NewScanner() *Scanner {
	return &Scanner{}
}

// Scan returns a Sequence, or a list of tokens, for the data string supplied.
// For example, the following message
//
//   Jan 12 06:49:42 irc sshd[7034]: Failed password for root from 218.161.81.238 port 4228 ssh2
//
// Returns the following Sequence:
//
//   Sequence{
//   	Token{TokenTime, FieldUnknown, "jan 12 06:49:42", false, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "irc", false, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "sshd", false, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "[", false, false, 0},
//   	Token{TokenInteger, FieldUnknown, "7034", false, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "]", false, false, 0},
//   	Token{TokenLiteral, FieldUnknown, ":", false, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "failed", false, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "password", false, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "for", false, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "root", false, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "from", false, false, 0},
//   	Token{TokenIPv4, FieldUnknown, "218.161.81.238", false, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "port", false, false, 0},
//   	Token{TokenInteger, FieldUnknown, "4228", false, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "ssh2", false, false, 0},
//   }
//
// The following message
//
//   id=firewall time="2005-03-18 14:01:43" fw=TOPSEC priv=4 recorder=kernel type=conn policy=504 proto=TCP rule=deny src=210.82.121.91 sport=4958 dst=61.229.37.85 dport=23124 smac=00:0b:5f:b2:1d:80 dmac=00:04:c1:8b:d8:82
//
// Will return
//   Sequence{
//   	Token{TokenLiteral, FieldUnknown, "id", true, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "=", false, false, 0},
//   	Token{TokenString, FieldUnknown, "firewall", false, true, 0},
//   	Token{TokenLiteral, FieldUnknown, "time", true, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "=", false, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "\"", false, false, 0},
//   	Token{TokenTime, FieldUnknown, "2005-03-18 14:01:43", false, true, 0},
//   	Token{TokenLiteral, FieldUnknown, "\"", false, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "fw", true, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "=", false, false, 0},
//   	Token{TokenString, FieldUnknown, "topsec", false, true, 0},
//   	Token{TokenLiteral, FieldUnknown, "priv", true, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "=", false, false, 0},
//   	Token{TokenInteger, FieldUnknown, "4", false, true, 0},
//   	Token{TokenLiteral, FieldUnknown, "recorder", true, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "=", false, false, 0},
//   	Token{TokenString, FieldUnknown, "kernel", false, true, 0},
//   	Token{TokenLiteral, FieldUnknown, "type", true, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "=", false, false, 0},
//   	Token{TokenString, FieldUnknown, "conn", false, true, 0},
//   	Token{TokenLiteral, FieldUnknown, "policy", true, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "=", false, false, 0},
//   	Token{TokenInteger, FieldUnknown, "504", false, true, 0},
//   	Token{TokenLiteral, FieldUnknown, "proto", true, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "=", false, false, 0},
//   	Token{TokenString, FieldUnknown, "tcp", false, true, 0},
//   	Token{TokenLiteral, FieldUnknown, "rule", true, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "=", false, false, 0},
//   	Token{TokenString, FieldUnknown, "deny", false, true, 0},
//   	Token{TokenLiteral, FieldUnknown, "src", true, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "=", false, false, 0},
//   	Token{TokenIPv4, FieldUnknown, "210.82.121.91", false, true, 0},
//   	Token{TokenLiteral, FieldUnknown, "sport", true, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "=", false, false, 0},
//   	Token{TokenInteger, FieldUnknown, "4958", false, true, 0},
//   	Token{TokenLiteral, FieldUnknown, "dst", true, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "=", false, false, 0},
//   	Token{TokenIPv4, FieldUnknown, "61.229.37.85", false, true, 0},
//   	Token{TokenLiteral, FieldUnknown, "dport", true, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "=", false, false, 0},
//   	Token{TokenInteger, FieldUnknown, "23124", false, true, 0},
//   	Token{TokenLiteral, FieldUnknown, "smac", true, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "=", false, false, 0},
//   	Token{TokenMac, FieldUnknown, "00:0b:5f:b2:1d:80", false, true, 0},
//   	Token{TokenLiteral, FieldUnknown, "dmac", true, false, 0},
//   	Token{TokenLiteral, FieldUnknown, "=", false, false, 0},
//   	Token{TokenMac, FieldUnknown, "00:04:c1:8b:d8:82", false, true, 0},
//   }
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

		// square and angle bracket
		square, angle bool

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

		switch t {
		case TokenMac, TokenLiteral, TokenURL, TokenTime:
			v = strings.ToLower(v)
		}

		token := Token{Type: t, Value: v, Field: FieldUnknown}

		if v[0] == '%' && v[len(v)-1] == '%' {
			var err error
			r := int64(0)

			// Check to see if it's a %something-N% token
			parts := strings.Split(v[:len(v)-1], "-")

			if len(parts) > 1 {
				r, err = strconv.ParseInt(parts[1], 0, 0)
				if err != nil {
					return ErrInvalidCount
				}

				v = parts[0] + "%"
			}

			token.Range = int(r)

			// is this a known TokenType or FieldType?
			isTypeToken := false

			if f2 := field2Token(v); f2.Field != FieldUnknown {
				token.Field = f2.Field
				token.Type = f2.Type
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
		case nss == 0 && v == "=" && !this.state.nextIsValue:
			// This means we hit something like "abc=", so we assume abc, which is the
			// last token, is a key. It also means the next token should be a value
			if len(this.tokens) >= 1 {
				this.tokens[len(this.tokens)-1].IsKey = true
				this.tokens[len(this.tokens)-1].Type = TokenLiteral
				this.tokens[len(this.tokens)-1].IsValue = false
				this.state.nextIsValue = true
			}

		case this.state.nextIsValue:
			switch v {
			/*
				case "'":
					if this.state.single {
						this.state.single = false
						this.state.valueDistance = 0
						this.state.nextIsValue = false
					} else {
						this.state.single = true
						this.state.valueDistance = 1
					}
			*/

			case "\"":
				if this.state.double {
					this.state.double = false
					this.state.valueDistance = 0
					this.state.nextIsValue = false
				} else {
					this.state.double = true
					this.state.valueDistance = 1
				}

			case "<":
				this.state.angle = true
				this.state.valueDistance = 1

			case ">":
				this.state.angle = false
				this.state.valueDistance = 0
				this.state.nextIsValue = false

			case "[":
				this.state.square = true
				this.state.valueDistance = 1

			case "]":
				this.state.square = false
				this.state.valueDistance = 0
				this.state.nextIsValue = false

			default:
				last := len(this.tokens) - 1
				if this.tokens[last].IsValue {
					// Last token is a value and we are inside a quote, so let's
					// merge with the last token
					if nss > 0 {
						this.tokens[last].Value += " " + v
					} else {
						this.tokens[last].Value += v
					}
					this.state.prevToken = this.tokens[last]

					if this.insideQuote() {
						this.state.valueDistance++
					}
					return nil
				}

				// Last token is NOT a value, so we need to create a new one
				token.IsValue = true

				if token.Type == TokenLiteral {
					token.Type = TokenString
				}

				if !this.insideQuote() {
					this.state.nextIsValue = false
					this.state.valueDistance = 0
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
					return timeLen, TokenTime, nil
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

	case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '-' || r == '_' || r == '/' || r == '#' || r == '\\' || r == '%' || r == '*' || r == '@' || r == '$' || r == '?':
		if r == '/' {
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
			this.state.single = true
			this.state.tokenStop = true
		} else if index != 0 && this.state.single == true {
			this.state.tokenStop = true
		} else if index == 0 && this.state.single == true {
			this.state.single = false
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
	//this.data = strings.ToLower(this.data)
}

func (this *message) insideQuote() bool {
	return this.state.single || this.state.double || this.state.angle || this.state.square
}
