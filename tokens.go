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
}

func (this Token) String() string {
	return fmt.Sprintf("{ Field=%q, Type=%q, Value=%q }", this.Field, this.Type, this.Value)
}

type (
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
	"%funknown%":   &Token{TokenUnknown, FieldUnknown, "%funknown%", false, false},
	"%msgtype%":    &Token{TokenInteger, FieldMsgType, "%msgtype%", false, false},
	"%msgclass%":   &Token{TokenString, FieldMsgClass, "%msgclass%", false, false},
	"%recvtime%":   &Token{TokenTS, FieldRecvTime, "%recvtime%", false, false},
	"%createtime%": &Token{TokenTS, FieldCreateTime, "%createtime%", false, false},
	"%severity%":   &Token{TokenInteger, FieldSeverity, "%severity%", false, false},
	"%priority%":   &Token{TokenInteger, FieldPriority, "%priority%", false, false},
	"%apphost%":    &Token{TokenString, FieldAppHost, "%apphost%", false, false},
	"%appipv4%":    &Token{TokenIPv4, FieldAppIPv4, "%appipv4%", false, false},
	"%appname%":    &Token{TokenString, FieldAppName, "%appname%", false, false},
	"%apptype%":    &Token{TokenString, FieldAppType, "%apptype%", false, false},
	"%srcdomain%":  &Token{TokenString, FieldSrcDomain, "%srcdomain%", false, false},
	"%srczone%":    &Token{TokenString, FieldSrcZone, "%srczone%", false, false},
	"%srchost%":    &Token{TokenString, FieldSrcHost, "%srchost%", false, false},
	"%srcipv4%":    &Token{TokenIPv4, FieldSrcIPv4, "%srcipv4%", false, false},
	"%srcipv4nat%": &Token{TokenIPv4, FieldSrcIPv4NAT, "%srcipv4nat%", false, false},
	"%srcipv6%":    &Token{TokenIPv6, FieldSrcIPv6, "%srcipv6%", false, false},
	"%srcport%":    &Token{TokenInteger, FieldSrcPort, "%srcport%", false, false},
	"%srcportnat%": &Token{TokenInteger, FieldSrcPortNAT, "%srcportnat%", false, false},
	"%srcmac%":     &Token{TokenMac, FieldSrcMac, "%srcmac%", false, false},
	"%srcuser%":    &Token{TokenString, FieldSrcUser, "%srcuser%", false, false},
	"%srcemail%":   &Token{TokenString, FieldSrcEmail, "%srcemail%", false, false},
	"%dstdomain%":  &Token{TokenString, FieldDstDomain, "%dstdomain%", false, false},
	"%dstzone%":    &Token{TokenString, FieldDstZone, "%dstzone%", false, false},
	"%dsthost%":    &Token{TokenString, FieldDstHost, "%dsthost%", false, false},
	"%dstipv4%":    &Token{TokenIPv4, FieldDstIPv4, "%dstipv4%", false, false},
	"%dstipv4nat%": &Token{TokenIPv4, FieldDstIPv4NAT, "%dstipv4nat%", false, false},
	"%dstipv6%":    &Token{TokenIPv6, FieldDstIPv6, "%dstipv6%", false, false},
	"%dstport%":    &Token{TokenInteger, FieldDstPort, "%dstport%", false, false},
	"%dstportnat%": &Token{TokenInteger, FieldDstPortNAT, "%dstportnat%", false, false},
	"%dstmac%":     &Token{TokenMac, FieldDstMac, "%dstmac%", false, false},
	"%dstuser%":    &Token{TokenString, FieldDstUser, "%dstuser%", false, false},
	"%dstemail%":   &Token{TokenString, FieldDstEmail, "%dstemail%", false, false},
	"%protocol%":   &Token{TokenString, FieldProtocol, "%protocol%", false, false},
	"%iniface%":    &Token{TokenString, FieldInIface, "%iniface%", false, false},
	"%outiface%":   &Token{TokenString, FieldOutIface, "%outiface%", false, false},
	"%policyid%":   &Token{TokenInteger, FieldPolicyID, "%policyid%", false, false},
	"%sessionid%":  &Token{TokenInteger, FieldSessionID, "%sessionid%", false, false},
	"%object%":     &Token{TokenString, FieldObject, "%object%", false, false},
	"%action%":     &Token{TokenString, FieldAction, "%action%", false, false},
	"%method%":     &Token{TokenString, FieldMethod, "%method%", false, false},
	"%methodtype%": &Token{TokenString, FieldMethodType, "%methodtype%", false, false},
	"%status%":     &Token{TokenString, FieldStatus, "%status%", false, false},
	"%reason%":     &Token{TokenString, FieldReason, "%reason%", false, false},
	"%bytesrecv%":  &Token{TokenInteger, FieldBytesRecv, "%bytesrecv%", false, false},
	"%bytessent%":  &Token{TokenInteger, FieldBytesSent, "%bytessent%", false, false},
	"%pktsrecv%":   &Token{TokenInteger, FieldPktsRecv, "%pktsrecv%", false, false},
	"%pktssent%":   &Token{TokenInteger, FieldPktsSent, "%pktssent%", false, false},
	"%duration%":   &Token{TokenString, FieldDuration, "%duration%", false, false},
}
