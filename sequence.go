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
	"strings"
)

type Sequence []Token

func (this Sequence) String() string {
	var p string

	for _, token := range this {
		if token.Field != FieldUnknown {
			p += token.Field.String() + " "
		} else if token.Type != TokenUnknown && token.Type != TokenLiteral {
			p += token.Type.String() + " "
		} else if token.Type == TokenLiteral {
			p += token.Value + " "
		}
	}

	return strings.TrimSpace(p)
}

func (this Sequence) Signature() string {
	var sig string

	for _, token := range this {
		switch {
		case token.Type != TokenUnknown && token.Type != TokenString && token.Type != TokenLiteral:
			sig += token.Type.String()

		case token.Type == TokenLiteral && len(token.Value) == 1:
			sig += token.Value
		}
	}

	/*
		h := fnv.New64a()
		if _, err := h.Write([]byte(sig)); err != nil {
			return err
		}

		hash := h.Sum64()
	*/

	return sig
}

func (this Sequence) LongString() string {
	var str string
	for i, t := range this {
		str += fmt.Sprintf("# %3d: %s\n", i, t)
	}

	return str[:len(str)-1]
}
