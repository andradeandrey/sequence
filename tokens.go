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

// Token is a piece of information extracted from a log message. The Scanner will do
// its best to determine the TokenType which could be a time stamp, IPv4 or IPv6
// address, a URL, a mac address, an integer or a floating point number. In addition,
// if the Scanner finds a token that's surrounded by %, e.g., %srcuser%, it will
// try to determine the correct field type the token represents.
type Token struct {
	// Type is the type of token the Value represents.
	Type TokenType

	// Field determines which field the Value should be.
	Field FieldType

	// Value is the extracted string from the log message.
	Value string

	// IsKey represents whether this token is a key in a key=value pair.
	IsKey bool

	// IsValue represents whether this token is a value in a key=value pair.
	IsValue bool

	// Range represents the number of tokens this field should consume. It is only
	// used if Field is not FieldUnknown.
	Range int
}

func (this Token) String() string {
	return fmt.Sprintf("{ Field=%q, Type=%q, Value=%q, IsKey=%t, IsValue=%t, Range=%d }",
		this.Field, this.Type, this.Value, this.IsKey, this.IsValue, this.Range)
}

type (
	// FieldType is the semantic representation of a token.
	FieldType int

	// Tokentype is the lexical representation of a token.
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
	TokenUnknown TokenType = iota // Unknown token
	TokenLiteral                  // Token is a fixed literal
	TokenTime                     // Token is a timestamp, in the format listed in TimeFormats
	TokenIPv4                     // Token is an IPv4 address, in the form of a.b.c.d
	TokenIPv6                     // Token is an IPv6 address, not currently supported
	TokenInteger                  // Token is an integer number
	TokenFloat                    // token is a floating point number
	TokenURL                      // Token is an URL, in the form of http://... or https://...
	TokenMac                      // Token is a mac address
	TokenString                   // Token is a string that reprensents multiple possible values
	token__END__                  // All token types must be inserted before this one
)

const (
	FieldUnknown    FieldType = iota
	FieldMsgType              // Type of message
	FieldMsgClass             // Class of the message
	FieldRecvTime             // When the message is received
	FieldCreateTime           // Timestamp that’s part of the log message, usually it’s the time of creation of the message.
	FieldSeverity             // The severity of the event, e.g., Emergency, …
	FieldPriority             // The pirority of the event
	FieldAppHost              // The hostname of the host where the log message is generated
	FieldAppIPv4              // The IP address of the host where the application that generated the log message is running on.
	FieldAppName              // The name of the application that generated the log message, e.g., fw01, ids02, sshd
	FieldAppType              // The type of application that generated the log message, e.g., CiscoPIX, Snort
	FieldSrcDomain            // The domain name of the initiator of the event, usually a Windows domain
	FieldSrcZone              // The originating zone
	FieldSrcHost              // The hostname of the originator of the event or connection.
	FieldSrcIPv4              // The IPv4 address of the originator of the event or connection.
	FieldSrcIPv4NAT           // The natted (network address translation) IP of the originator of the event or connection.
	FieldSrcIPv6              // The IPv6 address of the originator of the event or connection.
	FieldSrcPort              // The port number of the originating connection.
	FieldSrcPortNAT           // The natted port number of the originating connection.
	FieldSrcMac               // The mac address of the host that originated the connection.
	FieldSrcUser              // The user that originated the connection.
	FieldSrcEmail             // The originating email address
	FieldDstDomain            // The domain name of the destination of the event, usually a Windows domain
	FieldDstZone              // The destination zone
	FieldDstHost              // The hostname of the destination of the event or connection.
	FieldDstIPv4              // The IPv4 address of the destination of the event or connection.
	FieldDstIPv4NAT           // The natted (network address translation) IP of the destination of the event or connection.
	FieldDstIPv6              // The IPv6 address of the destination of the event or connection.
	FieldDstPort              // The destination port number of the connection.
	FieldDstPortNAT           // The natted destination port number of the connection.
	FieldDstMac               // The mac address of the destination host.
	FieldDstUser              // The user at the destination host.
	FieldDstEmail             // The destination email address
	FieldProtocol             // The protocol, such as TCP, UDP, ICMP, of the connection
	FieldInIface              // The incoming interface
	FieldOutIface             // The outgoing interface
	FieldPolicyID             // The policy ID
	FieldSessionID            // The session or process ID
	FieldObject               // The object affected.
	FieldAction               // The action taken
	FieldMethod               // The method in which the action was taken, for example, public key or password for ssh
	FieldMethodType           // the method type
	FieldStatus               // The status of the action taken
	FieldReason               // The reason for the action taken
	FieldBytesRecv            // The number of bytes received
	FieldBytesSent            // The number of bytes sent
	FieldPktsRecv             // The number of packets received
	FieldPktsSent             // The number of packets sent
	FieldDuration             // The duration of the session
	field__END__              // All field types must be inserted before this one
)

func (this TokenType) String() string {
	switch this {
	case TokenUnknown:
		return "%tunknown%"
	case TokenLiteral:
		return "%literal%"
	case TokenTime:
		return "%time%"
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
	case "%time%":
		return TokenTime
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
		return TokenTime
	case "%createtime%":
		return TokenTime
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
	"%recvtime%":   &Token{TokenTime, FieldRecvTime, "%recvtime%", false, false, 0},
	"%createtime%": &Token{TokenTime, FieldCreateTime, "%createtime%", false, false, 0},
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
		return Token{TokenTime, FieldRecvTime, "%recvtime%", false, false, 0}
	case "%createtime%":
		return Token{TokenTime, FieldCreateTime, "%createtime%", false, false, 0}
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
