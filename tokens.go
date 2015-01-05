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

import "fmt"

type Token struct {
	Type  TokenType
	Field FieldType
	Value string

	IsKey   bool
	IsValue bool

	Range int
}

func (this Token) String() string {
	return fmt.Sprintf("{ Field=%q, Type=%q, Value=%q }", this.Field, this.Type, this.Value)
}

type (
	// Semantic
	FieldType int
	TokenType int
)

const (
	partialMatchWeight = 1
	fullMatchWeight    = 2

	numFieldTypes    = int(field__END__) + 1
	numTokenTypes    = int(token__END__) + 1
	numAllTypes      = numFieldTypes + numTokenTypes
	minFixedChildren = numAllTypes
)

const (
	TokenUnknown TokenType = iota
	TokenLiteral
	TokenTS
	TokenIPv4
	TokenIPv6
	TokenInteger
	TokenFloat
	TokenURL
	TokenMac
	TokenString
	token__END__ // All token types must be inserted before this one
)

const (
	FieldUnknown FieldType = iota
	FieldMsgType
	FieldMsgClass
	FieldRecvTime
	FieldCreateTime
	FieldSeverity
	FieldPriority
	FieldAppHost
	FieldAppIPv4
	FieldAppName
	FieldAppType
	FieldSrcDomain
	FieldSrcZone
	FieldSrcHost
	FieldSrcIPv4
	FieldSrcIPv4NAT
	FieldSrcIPv6
	FieldSrcPort
	FieldSrcPortNAT
	FieldSrcMac
	FieldSrcUser
	FieldSrcEmail
	FieldDstDomain
	FieldDstZone
	FieldDstHost
	FieldDstIPv4
	FieldDstIPv4NAT
	FieldDstIPv6
	FieldDstPort
	FieldDstPortNAT
	FieldDstMac
	FieldDstUser
	FieldDstEmail
	FieldProtocol
	FieldInIface
	FieldOutIface
	FieldPolicyID
	FieldSessionID
	FieldObject
	FieldAction
	FieldMethod
	FieldMethodType
	FieldStatus
	FieldReason
	FieldBytesRecv
	FieldBytesSent
	FieldPktsRecv
	FieldPktsSent
	FieldDuration
	field__END__ // All field types must be inserted before this one
)

func (this TokenType) String() string {
	switch this {
	case TokenUnknown:
		return "%tunknown%"
	case TokenLiteral:
		return "%literal%"
	case TokenTS:
		return "%ts%"
	case TokenIPv4:
		return "%ipv4%"
	case TokenIPv6:
		return "%ipv6%"
	case TokenInteger:
		return "%integer%"
	case TokenFloat:
		return "%float%"
	case TokenURL:
		return "%url%"
	case TokenMac:
		return "%mac%"
	case TokenString:
		return "%string%"
	}

	return ""
}

func name2TokenType(s string) TokenType {
	switch s {
	case "%literal%":
		return TokenLiteral
	case "%ts%":
		return TokenTS
	case "%ipv4%":
		return TokenIPv4
	case "%ipv6%":
		return TokenIPv6
	case "%integer%":
		return TokenInteger
	case "%float%":
		return TokenFloat
	case "%url%":
		return TokenURL
	case "%mac%":
		return TokenMac
	case "%string%":
		return TokenString
	}

	return TokenUnknown
}

func (this FieldType) String() string {
	switch this {
	case FieldMsgType:
		return "%msgtype%"
	case FieldMsgClass:
		return "%msgclass%"
	case FieldRecvTime:
		return "%recvtime%"
	case FieldCreateTime:
		return "%createtime%"
	case FieldSeverity:
		return "%severity%"
	case FieldPriority:
		return "%priority%"
	case FieldAppHost:
		return "%apphost%"
	case FieldAppIPv4:
		return "%appipv4%"
	case FieldAppName:
		return "%appname%"
	case FieldAppType:
		return "%apptype%"
	case FieldSrcDomain:
		return "%srcdomain%"
	case FieldSrcZone:
		return "%srczone%"
	case FieldSrcHost:
		return "%srchost%"
	case FieldSrcIPv4:
		return "%srcipv4%"
	case FieldSrcIPv4NAT:
		return "%srcipv4nat%"
	case FieldSrcIPv6:
		return "%srcipv6%"
	case FieldSrcPort:
		return "%srcport%"
	case FieldSrcPortNAT:
		return "%srcportnat%"
	case FieldSrcMac:
		return "%srcmac%"
	case FieldSrcUser:
		return "%srcuser%"
	case FieldSrcEmail:
		return "%srcemail%"
	case FieldDstDomain:
		return "%dstdomain%"
	case FieldDstZone:
		return "%dstzone%"
	case FieldDstHost:
		return "%dsthost%"
	case FieldDstIPv4:
		return "%dstipv4%"
	case FieldDstIPv4NAT:
		return "%dstipv4nat%"
	case FieldDstIPv6:
		return "%dstipv6%"
	case FieldDstPort:
		return "%dstport%"
	case FieldDstPortNAT:
		return "%dstportnat%"
	case FieldDstMac:
		return "%dstmac%"
	case FieldDstUser:
		return "%dstuser%"
	case FieldDstEmail:
		return "%dstemail%"
	case FieldProtocol:
		return "%protocol%"
	case FieldInIface:
		return "%iniface%"
	case FieldOutIface:
		return "%outiface%"
	case FieldPolicyID:
		return "%policyid%"
	case FieldSessionID:
		return "%sessionid%"
	case FieldObject:
		return "%object%"
	case FieldAction:
		return "%action%"
	case FieldMethod:
		return "%method%"
	case FieldMethodType:
		return "%methodtype%"
	case FieldStatus:
		return "%status%"
	case FieldReason:
		return "%reason%"
	case FieldBytesRecv:
		return "%bytesrecv%"
	case FieldBytesSent:
		return "%bytessent%"
	case FieldPktsRecv:
		return "%pktsrecv%"
	case FieldPktsSent:
		return "%pktssent%"
	case FieldDuration:
		return "%duration%"
	}

	return "%funknown%"
}

func field2TokenType(s string) TokenType {
	switch s {
	case "%msgtype%":
		return TokenInteger
	case "%msgclass%":
		return TokenString
	case "%recvtime%":
		return TokenTS
	case "%createtime%":
		return TokenTS
	case "%severity%":
		return TokenInteger
	case "%priority%":
		return TokenInteger
	case "%apphost%":
		return TokenString
	case "%appipv4%":
		return TokenIPv4
	case "%appname%":
		return TokenString
	case "%apptype%":
		return TokenString
	case "%srcdomain%":
		return TokenString
	case "%srczone%":
		return TokenString
	case "%srchost%":
		return TokenString
	case "%srcipv4%":
		return TokenIPv4
	case "%srcipv4nat%":
		return TokenIPv4
	case "%srcipv6%":
		return TokenIPv6
	case "%srcport%":
		return TokenInteger
	case "%srcportnat%":
		return TokenInteger
	case "%srcmac%":
		return TokenMac
	case "%srcuser%":
		return TokenString
	case "%srcemail%":
		return TokenString
	case "%dstdomain%":
		return TokenString
	case "%dstzone%":
		return TokenString
	case "%dsthost%":
		return TokenString
	case "%dstipv4%":
		return TokenIPv4
	case "%dstipv4nat%":
		return TokenIPv4
	case "%dstipv6%":
		return TokenIPv6
	case "%dstport%":
		return TokenInteger
	case "%dstportnat%":
		return TokenInteger
	case "%dstmac%":
		return TokenMac
	case "%dstuser%":
		return TokenString
	case "%dstemail%":
		return TokenString
	case "%protocol%":
		return TokenString
	case "%iniface%":
		return TokenString
	case "%outiface%":
		return TokenString
	case "%policyid%":
		return TokenInteger
	case "%sessionid%":
		return TokenInteger
	case "%object%":
		return TokenString
	case "%action%":
		return TokenString
	case "%method%":
		return TokenString
	case "%methodtype%":
		return TokenString
	case "%status%":
		return TokenString
	case "%reason%":
		return TokenString
	case "%bytesrecv%":
		return TokenInteger
	case "%bytessent%":
		return TokenInteger
	case "%pktsrecv%":
		return TokenInteger
	case "%pktssent%":
		return TokenInteger
	case "%duration%":
		return TokenString
	}

	return TokenUnknown
}

var fieldTokenMap map[string]*Token = map[string]*Token{
	"%funknown%":   &Token{TokenUnknown, FieldUnknown, "%funknown%", false, false, 0},
	"%msgtype%":    &Token{TokenInteger, FieldMsgType, "%msgtype%", false, false, 0},
	"%msgclass%":   &Token{TokenString, FieldMsgClass, "%msgclass%", false, false, 0},
	"%recvtime%":   &Token{TokenTS, FieldRecvTime, "%recvtime%", false, false, 0},
	"%createtime%": &Token{TokenTS, FieldCreateTime, "%createtime%", false, false, 0},
	"%severity%":   &Token{TokenInteger, FieldSeverity, "%severity%", false, false, 0},
	"%priority%":   &Token{TokenInteger, FieldPriority, "%priority%", false, false, 0},
	"%apphost%":    &Token{TokenString, FieldAppHost, "%apphost%", false, false, 0},
	"%appipv4%":    &Token{TokenIPv4, FieldAppIPv4, "%appipv4%", false, false, 0},
	"%appname%":    &Token{TokenString, FieldAppName, "%appname%", false, false, 0},
	"%apptype%":    &Token{TokenString, FieldAppType, "%apptype%", false, false, 0},
	"%srcdomain%":  &Token{TokenString, FieldSrcDomain, "%srcdomain%", false, false, 0},
	"%srczone%":    &Token{TokenString, FieldSrcZone, "%srczone%", false, false, 0},
	"%srchost%":    &Token{TokenString, FieldSrcHost, "%srchost%", false, false, 0},
	"%srcipv4%":    &Token{TokenIPv4, FieldSrcIPv4, "%srcipv4%", false, false, 0},
	"%srcipv4nat%": &Token{TokenIPv4, FieldSrcIPv4NAT, "%srcipv4nat%", false, false, 0},
	"%srcipv6%":    &Token{TokenIPv6, FieldSrcIPv6, "%srcipv6%", false, false, 0},
	"%srcport%":    &Token{TokenInteger, FieldSrcPort, "%srcport%", false, false, 0},
	"%srcportnat%": &Token{TokenInteger, FieldSrcPortNAT, "%srcportnat%", false, false, 0},
	"%srcmac%":     &Token{TokenMac, FieldSrcMac, "%srcmac%", false, false, 0},
	"%srcuser%":    &Token{TokenString, FieldSrcUser, "%srcuser%", false, false, 0},
	"%srcemail%":   &Token{TokenString, FieldSrcEmail, "%srcemail%", false, false, 0},
	"%dstdomain%":  &Token{TokenString, FieldDstDomain, "%dstdomain%", false, false, 0},
	"%dstzone%":    &Token{TokenString, FieldDstZone, "%dstzone%", false, false, 0},
	"%dsthost%":    &Token{TokenString, FieldDstHost, "%dsthost%", false, false, 0},
	"%dstipv4%":    &Token{TokenIPv4, FieldDstIPv4, "%dstipv4%", false, false, 0},
	"%dstipv4nat%": &Token{TokenIPv4, FieldDstIPv4NAT, "%dstipv4nat%", false, false, 0},
	"%dstipv6%":    &Token{TokenIPv6, FieldDstIPv6, "%dstipv6%", false, false, 0},
	"%dstport%":    &Token{TokenInteger, FieldDstPort, "%dstport%", false, false, 0},
	"%dstportnat%": &Token{TokenInteger, FieldDstPortNAT, "%dstportnat%", false, false, 0},
	"%dstmac%":     &Token{TokenMac, FieldDstMac, "%dstmac%", false, false, 0},
	"%dstuser%":    &Token{TokenString, FieldDstUser, "%dstuser%", false, false, 0},
	"%dstemail%":   &Token{TokenString, FieldDstEmail, "%dstemail%", false, false, 0},
	"%protocol%":   &Token{TokenString, FieldProtocol, "%protocol%", false, false, 0},
	"%iniface%":    &Token{TokenString, FieldInIface, "%iniface%", false, false, 0},
	"%outiface%":   &Token{TokenString, FieldOutIface, "%outiface%", false, false, 0},
	"%policyid%":   &Token{TokenInteger, FieldPolicyID, "%policyid%", false, false, 0},
	"%sessionid%":  &Token{TokenInteger, FieldSessionID, "%sessionid%", false, false, 0},
	"%object%":     &Token{TokenString, FieldObject, "%object%", false, false, 0},
	"%action%":     &Token{TokenString, FieldAction, "%action%", false, false, 0},
	"%method%":     &Token{TokenString, FieldMethod, "%method%", false, false, 0},
	"%methodtype%": &Token{TokenString, FieldMethodType, "%methodtype%", false, false, 0},
	"%status%":     &Token{TokenString, FieldStatus, "%status%", false, false, 0},
	"%reason%":     &Token{TokenString, FieldReason, "%reason%", false, false, 0},
	"%bytesrecv%":  &Token{TokenInteger, FieldBytesRecv, "%bytesrecv%", false, false, 0},
	"%bytessent%":  &Token{TokenInteger, FieldBytesSent, "%bytessent%", false, false, 0},
	"%pktsrecv%":   &Token{TokenInteger, FieldPktsRecv, "%pktsrecv%", false, false, 0},
	"%pktssent%":   &Token{TokenInteger, FieldPktsSent, "%pktssent%", false, false, 0},
	"%duration%":   &Token{TokenString, FieldDuration, "%duration%", false, false, 0},
}

func field2Token(f string) Token {
	switch f {
	case "%msgtype%":
		return Token{TokenInteger, FieldMsgType, "%msgtype%", false, false, 0}
	case "%msgclass%":
		return Token{TokenString, FieldMsgClass, "%msgclass%", false, false, 0}
	case "%recvtime%":
		return Token{TokenTS, FieldRecvTime, "%recvtime%", false, false, 0}
	case "%createtime%":
		return Token{TokenTS, FieldCreateTime, "%createtime%", false, false, 0}
	case "%severity%":
		return Token{TokenInteger, FieldSeverity, "%severity%", false, false, 0}
	case "%priority%":
		return Token{TokenInteger, FieldPriority, "%priority%", false, false, 0}
	case "%apphost%":
		return Token{TokenString, FieldAppHost, "%apphost%", false, false, 0}
	case "%appipv4%":
		return Token{TokenIPv4, FieldAppIPv4, "%appipv4%", false, false, 0}
	case "%appname%":
		return Token{TokenString, FieldAppName, "%appname%", false, false, 0}
	case "%apptype%":
		return Token{TokenString, FieldAppType, "%apptype%", false, false, 0}
	case "%srcdomain%":
		return Token{TokenString, FieldSrcDomain, "%srcdomain%", false, false, 0}
	case "%srczone%":
		return Token{TokenString, FieldSrcZone, "%srczone%", false, false, 0}
	case "%srchost%":
		return Token{TokenString, FieldSrcHost, "%srchost%", false, false, 0}
	case "%srcipv4%":
		return Token{TokenIPv4, FieldSrcIPv4, "%srcipv4%", false, false, 0}
	case "%srcipv4nat%":
		return Token{TokenIPv4, FieldSrcIPv4NAT, "%srcipv4nat%", false, false, 0}
	case "%srcipv6%":
		return Token{TokenIPv6, FieldSrcIPv6, "%srcipv6%", false, false, 0}
	case "%srcport%":
		return Token{TokenInteger, FieldSrcPort, "%srcport%", false, false, 0}
	case "%srcportnat%":
		return Token{TokenInteger, FieldSrcPortNAT, "%srcportnat%", false, false, 0}
	case "%srcmac%":
		return Token{TokenMac, FieldSrcMac, "%srcmac%", false, false, 0}
	case "%srcuser%":
		return Token{TokenString, FieldSrcUser, "%srcuser%", false, false, 0}
	case "%srcemail%":
		return Token{TokenString, FieldSrcEmail, "%srcemail%", false, false, 0}
	case "%dstdomain%":
		return Token{TokenString, FieldDstDomain, "%dstdomain%", false, false, 0}
	case "%dstzone%":
		return Token{TokenString, FieldDstZone, "%dstzone%", false, false, 0}
	case "%dsthost%":
		return Token{TokenString, FieldDstHost, "%dsthost%", false, false, 0}
	case "%dstipv4%":
		return Token{TokenIPv4, FieldDstIPv4, "%dstipv4%", false, false, 0}
	case "%dstipv4nat%":
		return Token{TokenIPv4, FieldDstIPv4NAT, "%dstipv4nat%", false, false, 0}
	case "%dstipv6%":
		return Token{TokenIPv6, FieldDstIPv6, "%dstipv6%", false, false, 0}
	case "%dstport%":
		return Token{TokenInteger, FieldDstPort, "%dstport%", false, false, 0}
	case "%dstportnat%":
		return Token{TokenInteger, FieldDstPortNAT, "%dstportnat%", false, false, 0}
	case "%dstmac%":
		return Token{TokenMac, FieldDstMac, "%dstmac%", false, false, 0}
	case "%dstuser%":
		return Token{TokenString, FieldDstUser, "%dstuser%", false, false, 0}
	case "%dstemail%":
		return Token{TokenString, FieldDstEmail, "%dstemail%", false, false, 0}
	case "%protocol%":
		return Token{TokenString, FieldProtocol, "%protocol%", false, false, 0}
	case "%iniface%":
		return Token{TokenString, FieldInIface, "%iniface%", false, false, 0}
	case "%outiface%":
		return Token{TokenString, FieldOutIface, "%outiface%", false, false, 0}
	case "%policyid%":
		return Token{TokenInteger, FieldPolicyID, "%policyid%", false, false, 0}
	case "%sessionid%":
		return Token{TokenInteger, FieldSessionID, "%sessionid%", false, false, 0}
	case "%object%":
		return Token{TokenString, FieldObject, "%object%", false, false, 0}
	case "%action%":
		return Token{TokenString, FieldAction, "%action%", false, false, 0}
	case "%method%":
		return Token{TokenString, FieldMethod, "%method%", false, false, 0}
	case "%methodtype%":
		return Token{TokenString, FieldMethodType, "%methodtype%", false, false, 0}
	case "%status%":
		return Token{TokenString, FieldStatus, "%status%", false, false, 0}
	case "%reason%":
		return Token{TokenString, FieldReason, "%reason%", false, false, 0}
	case "%bytesrecv%":
		return Token{TokenInteger, FieldBytesRecv, "%bytesrecv%", false, false, 0}
	case "%bytessent%":
		return Token{TokenInteger, FieldBytesSent, "%bytessent%", false, false, 0}
	case "%pktsrecv%":
		return Token{TokenInteger, FieldPktsRecv, "%pktsrecv%", false, false, 0}
	case "%pktssent%":
		return Token{TokenInteger, FieldPktsSent, "%pktssent%", false, false, 0}
	case "%duration%":
		return Token{TokenString, FieldDuration, "%duration%", false, false, 0}
	}

	return Token{TokenUnknown, FieldUnknown, "%funknown%", false, false, 0}
}
