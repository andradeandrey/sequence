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
	"strings"
	"testing"

	"github.com/dataence/assert"
)

var (
	testdata map[string]string = map[string]string{
		"jan 12 06:49:41 irc sshd[7034]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=218-161-81-238.hinet-ip.hinet.net  user=root":                                                                                                                                  "%ts%[%integer%]:(:):;==%integer%=%integer%====",
		"jan 12 06:49:42 irc sshd[7034]: failed password for root from 218.161.81.238 port 4228 ssh2":                                                                                                                                                                                                           "%ts%[%integer%]:%ipv4%%integer%",
		"9.26.157.45 - - [16/jan/2003:21:22:59 -0500] \"get /wssamples/ http/1.1\" 200 1576":                                                                                                                                                                                                                    "%ipv4%--[%ts%]\"\"%integer%%integer%",
		"209.36.88.3 - - [03/may/2004:01:19:07 +0000] \"get http://npkclzicp.xihudohtd.ngm.au/abramson/eiyscmeqix.ac;jsessionid=b0l0v000u0?sid=00000000&sy=afr&kw=goldman&pb=fin&dt=selectrange&dr=0month&so=relevance&st=nw&ss=afr&sf=article&rc=00&clspage=0&docid=fin0000000r0jl000d00 http/1.0\" 200 27981": "%ipv4%--[%ts%]\"%url%\"%integer%%integer%",
		"4/5/2012 17:55,172.23.1.101,1101,172.23.0.10,139, generic protocol command decode,3, [1:2100538:17] gpl netbios smb ipc$ unicode share access ,tcp ttl:128 tos:0x0 id:1643 iplen:20 dgmlen:122 df,***ap*** seq: 0xcef93f32  ack: 0xc40c0bb  n: 0xfc9c  tcplen: 20,":                                    "%ts%,%ipv4%,%integer%,%ipv4%,%integer%,,%integer%,[%integer%:%integer%:%integer%],:%integer%::%integer%:%integer%:%integer%,::n::%integer%,",
		"2012-04-05 17:54:47     local4.info     172.23.0.1      %asa-6-302015: built outbound udp connection 1315679 for outside:193.0.14.129/53 (193.0.14.129/53) to inside:172.23.0.10/64048 (10.32.0.1/52130)":                                                                                              "%ts%%ipv4%:%integer%:%ipv4%/%integer%(%ipv4%/%integer%):%ipv4%/%integer%(%ipv4%/%integer%)",
		"may  2 19:00:02 dlfssrv sendmail[18980]: taa18980: from user daemon: size is 596, class is 0, priority is 30596, and nrcpts=1, message id is <200305021400.taa18980@dlfssrv.in.ibm.com>, relay=daemon@localhost":                                                                                       "%ts%[%integer%]:::%integer%,%integer%,%integer%,=%integer%,<>,=",
		"jan 12 06:49:56 irc last message repeated 6 times":                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  "%ts%%integer%",
		"9.26.157.44 - - [16/jan/2003:21:22:59 -0500] \"get http://wssamples http/1.1\" 301 315":                                                                                                                                                                                                                                                                                                                                                                                                                                             "%ipv4%--[%ts%]\"%url%\"%integer%%integer%",
		"2012-04-05 17:51:26     local4.info     172.23.0.1      %asa-6-302016: teardown udp connection 1315632 for inside:172.23.0.2/514 to identity:172.23.0.1/514 duration 0:09:23 bytes 7999":                                                                                                                                                                                                                                                                                                                                            "%ts%%ipv4%:%integer%:%ipv4%/%integer%:%ipv4%/%integer%%integer%:%integer%:%integer%%integer%",
		"id=firewall time=\"2005-03-18 14:01:43\" fw=topsec priv=4 recorder=kernel type=conn policy=504 proto=tcp rule=deny src=210.82.121.91 sport=4958 dst=61.229.37.85 dport=23124 smac=00:0b:5f:b2:1d:80 dmac=00:04:c1:8b:d8:82":                                                                                                                                                                                                                                                                                                         "==\"%ts%\"==%integer%===%integer%===%ipv4%=%integer%=%ipv4%=%integer%=%mac%=%mac%",
		"mar 01 09:42:03.875 pffbisvr smtp[2424]: 334 warning: denied access to command 'ehlo vishwakstg1.msn.vishwak.net' from [209.235.210.30]":                                                                                                                                                                                                                                                                                                                                                                                            "%ts%[%integer%]:%integer%:''[%ipv4%]",
		"mar 01 09:45:02.596 pffbisvr smtp[2424]: 121 statistics: duration=181.14 user=<egreetings@vishwak.com> id=zduqd sent=1440 rcvd=356 srcif=d45f49a2-b30 src=209.235.210.30/61663 cldst=192.216.179.206/25 svsrc=172.17.74.195/8423 dstif=fd3c875c-064 dst=172.17.74.52/25 op=\"to 1 recips\" arg=<vishwakstg1ojte15fo000033b4@vishwakstg1.msn.vishwak.net> result=\"250 m2004030109385301402 message accepted for delivery\" proto=smtp rule=131 (denied access to command 'ehlo vishwakstg1.msn.vishwak.net' from [209.235.210.30])": "%ts%[%integer%]:%integer%:=%float%=<>==%integer%=%integer%==%ipv4%/%integer%=%ipv4%/%integer%=%ipv4%/%integer%==%ipv4%/%integer%=\"%integer%\"=<>=\"%integer%\"==%integer%(''[%ipv4%])",
	}
)

func TestMessageSignature(t *testing.T) {
	msg := &message{}

	for data, sig := range testdata {
		msg.data = data
		err := msg.tokenize()
		assert.NoError(t, true, err)

		newsig := msg.tokens.Signature()
		//glog.Debugf("newsig = %s", newsig)
		assert.Equal(t, true, sig, newsig)

		//glog.Debugf("\n%s\n%s\n%s", data, newsig, msg.printTokens())
	}
}

var (
	messages map[string]Sequence = map[string]Sequence{
		"Jan 12 06:49:41 irc sshd[7034]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=218-161-81-238.hinet-ip.hinet.net  user=root": Sequence{
			Token{TokenTS, FieldUnknown, "jan 12 06:49:41", false, false},
			Token{TokenLiteral, FieldUnknown, "irc", false, false},
			Token{TokenLiteral, FieldUnknown, "sshd", false, false},
			Token{TokenLiteral, FieldUnknown, "[", false, false},
			Token{TokenInteger, FieldUnknown, "7034", false, false},
			Token{TokenLiteral, FieldUnknown, "]", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenLiteral, FieldUnknown, "pam_unix", false, false},
			Token{TokenLiteral, FieldUnknown, "(", false, false},
			Token{TokenLiteral, FieldUnknown, "sshd", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenLiteral, FieldUnknown, "auth", false, false},
			Token{TokenLiteral, FieldUnknown, ")", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenLiteral, FieldUnknown, "authentication", false, false},
			Token{TokenLiteral, FieldUnknown, "failure", false, false},
			Token{TokenLiteral, FieldUnknown, ";", false, false},
			Token{TokenLiteral, FieldUnknown, "logname", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenLiteral, FieldUnknown, "uid", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenInteger, FieldUnknown, "0", false, true},
			Token{TokenLiteral, FieldUnknown, "euid", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenInteger, FieldUnknown, "0", false, true},
			Token{TokenLiteral, FieldUnknown, "tty", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenString, FieldUnknown, "ssh", false, true},
			Token{TokenLiteral, FieldUnknown, "ruser", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenLiteral, FieldUnknown, "rhost", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenString, FieldUnknown, "218-161-81-238.hinet-ip.hinet.net", false, true},
			Token{TokenLiteral, FieldUnknown, "user", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenString, FieldUnknown, "root", false, true},
		},

		"Jan 12 06:49:42 irc sshd[7034]: Failed password for root from 218.161.81.238 port 4228 ssh2": Sequence{
			Token{TokenTS, FieldUnknown, "jan 12 06:49:42", false, false},
			Token{TokenLiteral, FieldUnknown, "irc", false, false},
			Token{TokenLiteral, FieldUnknown, "sshd", false, false},
			Token{TokenLiteral, FieldUnknown, "[", false, false},
			Token{TokenInteger, FieldUnknown, "7034", false, false},
			Token{TokenLiteral, FieldUnknown, "]", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenLiteral, FieldUnknown, "failed", false, false},
			Token{TokenLiteral, FieldUnknown, "password", false, false},
			Token{TokenLiteral, FieldUnknown, "for", false, false},
			Token{TokenLiteral, FieldUnknown, "root", false, false},
			Token{TokenLiteral, FieldUnknown, "from", false, false},
			Token{TokenIPv4, FieldUnknown, "218.161.81.238", false, false},
			Token{TokenLiteral, FieldUnknown, "port", false, false},
			Token{TokenInteger, FieldUnknown, "4228", false, false},
			Token{TokenLiteral, FieldUnknown, "ssh2", false, false},
		},

		//"Jan 13 17:25:59 jlz sshd[19322]: Accepted password for jlz from 108.61.8.124 port 56731 ssh2",
		//"Jan 12 14:44:48 irc sshd[11084]: Accepted publickey for jlz from 76.21.0.16 port 36609 ssh2",
		"Jan 12 06:49:56 irc last message repeated 6 times": Sequence{
			Token{TokenTS, FieldUnknown, "jan 12 06:49:56", false, false},
			Token{TokenLiteral, FieldUnknown, "irc", false, false},
			Token{TokenLiteral, FieldUnknown, "last", false, false},
			Token{TokenLiteral, FieldUnknown, "message", false, false},
			Token{TokenLiteral, FieldUnknown, "repeated", false, false},
			Token{TokenInteger, FieldUnknown, "6", false, false},
			Token{TokenLiteral, FieldUnknown, "times", false, false},
		},

		"9.26.157.44 - - [16/Jan/2003:21:22:59 -0500] \"GET http://WSsamples HTTP/1.1\" 301 315": Sequence{
			Token{TokenIPv4, FieldUnknown, "9.26.157.44", false, false},
			Token{TokenLiteral, FieldUnknown, "-", false, false},
			Token{TokenLiteral, FieldUnknown, "-", false, false},
			Token{TokenLiteral, FieldUnknown, "[", false, false},
			Token{TokenTS, FieldUnknown, "16/jan/2003:21:22:59 -0500", false, false},
			Token{TokenLiteral, FieldUnknown, "]", false, false},
			Token{TokenLiteral, FieldUnknown, "\"", false, false},
			Token{TokenLiteral, FieldUnknown, "get", false, false},
			Token{TokenURL, FieldUnknown, "http://wssamples", false, false},
			Token{TokenLiteral, FieldUnknown, "http/1.1", false, false},
			Token{TokenLiteral, FieldUnknown, "\"", false, false},
			Token{TokenInteger, FieldUnknown, "301", false, false},
			Token{TokenInteger, FieldUnknown, "315", false, false},
		},

		"9.26.157.45 - - [16/Jan/2003:21:22:59 -0500] \"GET /WSsamples/ HTTP/1.1\" 200 1576": Sequence{
			Token{TokenIPv4, FieldUnknown, "9.26.157.45", false, false},
			Token{TokenLiteral, FieldUnknown, "-", false, false},
			Token{TokenLiteral, FieldUnknown, "-", false, false},
			Token{TokenLiteral, FieldUnknown, "[", false, false},
			Token{TokenTS, FieldUnknown, "16/jan/2003:21:22:59 -0500", false, false},
			Token{TokenLiteral, FieldUnknown, "]", false, false},
			Token{TokenLiteral, FieldUnknown, "\"", false, false},
			Token{TokenLiteral, FieldUnknown, "get", false, false},
			Token{TokenLiteral, FieldUnknown, "/wssamples/", false, false},
			Token{TokenLiteral, FieldUnknown, "http/1.1", false, false},
			Token{TokenLiteral, FieldUnknown, "\"", false, false},
			Token{TokenInteger, FieldUnknown, "200", false, false},
			Token{TokenInteger, FieldUnknown, "1576", false, false},
		},

		"209.36.88.3 - - [03/May/2004:01:19:07 +0000] \"GET http://npkclzicp.xihudohtd.ngm.au/abramson/eiyscmeqix.ac;jsessionid=b0l0v000u0?sid=00000000&sy=afr&kw=goldman&pb=fin&dt=selectRange&dr=0month&so=relevance&st=nw&ss=AFR&sf=article&rc=00&clsPage=0&docID=FIN0000000R0JL000D00 HTTP/1.0\" 200 27981": Sequence{
			Token{TokenIPv4, FieldUnknown, "209.36.88.3", false, false},
			Token{TokenLiteral, FieldUnknown, "-", false, false},
			Token{TokenLiteral, FieldUnknown, "-", false, false},
			Token{TokenLiteral, FieldUnknown, "[", false, false},
			Token{TokenTS, FieldUnknown, "03/may/2004:01:19:07 +0000", false, false},
			Token{TokenLiteral, FieldUnknown, "]", false, false},
			Token{TokenLiteral, FieldUnknown, "\"", false, false},
			Token{TokenLiteral, FieldUnknown, "get", false, false},
			Token{TokenURL, FieldUnknown, strings.ToLower("http://npkclzicp.xihudohtd.ngm.au/abramson/eiyscmeqix.ac;jsessionid=b0l0v000u0?sid=00000000&sy=afr&kw=goldman&pb=fin&dt=selectRange&dr=0month&so=relevance&st=nw&ss=AFR&sf=article&rc=00&clsPage=0&docID=FIN0000000R0JL000D00"), false, false},
			Token{TokenLiteral, FieldUnknown, "http/1.0", false, false},
			Token{TokenLiteral, FieldUnknown, "\"", false, false},
			Token{TokenInteger, FieldUnknown, "200", false, false},
			Token{TokenInteger, FieldUnknown, "27981", false, false},
		},

		"4/5/2012 17:55,172.23.1.101,1101,172.23.0.10,139, Generic Protocol Command Decode,3, [1:2100538:17] GPL NETBIOS SMB IPC$ unicode share access ,TCP TTL:128 TOS:0x0 ID:1643 IpLen:20 DgmLen:122 DF,***AP*** Seq: 0xCEF93F32  Ack: 0xC40C0BB  n: 0xFC9C  TcpLen: 20,": Sequence{
			Token{TokenTS, FieldUnknown, "4/5/2012 17:55", false, false},
			Token{TokenLiteral, FieldUnknown, ",", false, false},
			Token{TokenIPv4, FieldUnknown, "172.23.1.101", false, false},
			Token{TokenLiteral, FieldUnknown, ",", false, false},
			Token{TokenInteger, FieldUnknown, "1101", false, false},
			Token{TokenLiteral, FieldUnknown, ",", false, false},
			Token{TokenIPv4, FieldUnknown, "172.23.0.10", false, false},
			Token{TokenLiteral, FieldUnknown, ",", false, false},
			Token{TokenInteger, FieldUnknown, "139", false, false},
			Token{TokenLiteral, FieldUnknown, ",", false, false},
			Token{TokenLiteral, FieldUnknown, "generic", false, false},
			Token{TokenLiteral, FieldUnknown, "protocol", false, false},
			Token{TokenLiteral, FieldUnknown, "command", false, false},
			Token{TokenLiteral, FieldUnknown, "decode", false, false},
			Token{TokenLiteral, FieldUnknown, ",", false, false},
			Token{TokenInteger, FieldUnknown, "3", false, false},
			Token{TokenLiteral, FieldUnknown, ",", false, false},
			Token{TokenLiteral, FieldUnknown, "[", false, false},
			Token{TokenInteger, FieldUnknown, "1", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenInteger, FieldUnknown, "2100538", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenInteger, FieldUnknown, "17", false, false},
			Token{TokenLiteral, FieldUnknown, "]", false, false},
			Token{TokenLiteral, FieldUnknown, "gpl", false, false},
			Token{TokenLiteral, FieldUnknown, "netbios", false, false},
			Token{TokenLiteral, FieldUnknown, "smb", false, false},
			Token{TokenLiteral, FieldUnknown, "ipc$", false, false},
			Token{TokenLiteral, FieldUnknown, "unicode", false, false},
			Token{TokenLiteral, FieldUnknown, "share", false, false},
			Token{TokenLiteral, FieldUnknown, "access", false, false},
			Token{TokenLiteral, FieldUnknown, ",", false, false},
			Token{TokenLiteral, FieldUnknown, "tcp", false, false},
			Token{TokenLiteral, FieldUnknown, "ttl", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenInteger, FieldUnknown, "128", false, false},
			Token{TokenLiteral, FieldUnknown, "tos", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenLiteral, FieldUnknown, "0x0", false, false},
			Token{TokenLiteral, FieldUnknown, "id", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenInteger, FieldUnknown, "1643", false, false},
			Token{TokenLiteral, FieldUnknown, "iplen", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenInteger, FieldUnknown, "20", false, false},
			Token{TokenLiteral, FieldUnknown, "dgmlen", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenInteger, FieldUnknown, "122", false, false},
			Token{TokenLiteral, FieldUnknown, "df", false, false},
			Token{TokenLiteral, FieldUnknown, ",", false, false},
			Token{TokenLiteral, FieldUnknown, "***ap***", false, false},
			Token{TokenLiteral, FieldUnknown, "seq", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenLiteral, FieldUnknown, "0xcef93f32", false, false},
			Token{TokenLiteral, FieldUnknown, "ack", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenLiteral, FieldUnknown, "0xc40c0bb", false, false},
			Token{TokenLiteral, FieldUnknown, "n", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenLiteral, FieldUnknown, "0xfc9c", false, false},
			Token{TokenLiteral, FieldUnknown, "tcplen", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenInteger, FieldUnknown, "20", false, false},
			Token{TokenLiteral, FieldUnknown, ",", false, false},
		},

		"2012-04-05 17:51:26     Local4.Info     172.23.0.1      %ASA-6-302016: Teardown UDP connection 1315632 for inside:172.23.0.2/514 to identity:172.23.0.1/514 duration 0:09:23 bytes 7999": Sequence{
			Token{TokenTS, FieldUnknown, "2012-04-05 17:51:26", false, false},
			Token{TokenLiteral, FieldUnknown, "local4.info", false, false},
			Token{TokenIPv4, FieldUnknown, "172.23.0.1", false, false},
			Token{TokenLiteral, FieldUnknown, "%asa-6-302016", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenLiteral, FieldUnknown, "teardown", false, false},
			Token{TokenLiteral, FieldUnknown, "udp", false, false},
			Token{TokenLiteral, FieldUnknown, "connection", false, false},
			Token{TokenInteger, FieldUnknown, "1315632", false, false},
			Token{TokenLiteral, FieldUnknown, "for", false, false},
			Token{TokenLiteral, FieldUnknown, "inside", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenIPv4, FieldUnknown, "172.23.0.2", false, false},
			Token{TokenLiteral, FieldUnknown, "/", false, false},
			Token{TokenInteger, FieldUnknown, "514", false, false},
			Token{TokenLiteral, FieldUnknown, "to", false, false},
			Token{TokenLiteral, FieldUnknown, "identity", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenIPv4, FieldUnknown, "172.23.0.1", false, false},
			Token{TokenLiteral, FieldUnknown, "/", false, false},
			Token{TokenInteger, FieldUnknown, "514", false, false},
			Token{TokenLiteral, FieldUnknown, "duration", false, false},
			Token{TokenInteger, FieldUnknown, "0", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenInteger, FieldUnknown, "09", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenInteger, FieldUnknown, "23", false, false},
			Token{TokenLiteral, FieldUnknown, "bytes", false, false},
			Token{TokenInteger, FieldUnknown, "7999", false, false},
		},

		"2012-04-05 17:54:47     Local4.Info     172.23.0.1      %ASA-6-302015: Built outbound UDP connection 1315679 for outside:193.0.14.129/53 (193.0.14.129/53) to inside:172.23.0.10/64048 (10.32.0.1/52130)": Sequence{
			Token{TokenTS, FieldUnknown, "2012-04-05 17:54:47", false, false},
			Token{TokenLiteral, FieldUnknown, "local4.info", false, false},
			Token{TokenIPv4, FieldUnknown, "172.23.0.1", false, false},
			Token{TokenLiteral, FieldUnknown, "%asa-6-302015", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenLiteral, FieldUnknown, "built", false, false},
			Token{TokenLiteral, FieldUnknown, "outbound", false, false},
			Token{TokenLiteral, FieldUnknown, "udp", false, false},
			Token{TokenLiteral, FieldUnknown, "connection", false, false},
			Token{TokenInteger, FieldUnknown, "1315679", false, false},
			Token{TokenLiteral, FieldUnknown, "for", false, false},
			Token{TokenLiteral, FieldUnknown, "outside", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenIPv4, FieldUnknown, "193.0.14.129", false, false},
			Token{TokenLiteral, FieldUnknown, "/", false, false},
			Token{TokenInteger, FieldUnknown, "53", false, false},
			Token{TokenLiteral, FieldUnknown, "(", false, false},
			Token{TokenIPv4, FieldUnknown, "193.0.14.129", false, false},
			Token{TokenLiteral, FieldUnknown, "/", false, false},
			Token{TokenInteger, FieldUnknown, "53", false, false},
			Token{TokenLiteral, FieldUnknown, ")", false, false},
			Token{TokenLiteral, FieldUnknown, "to", false, false},
			Token{TokenLiteral, FieldUnknown, "inside", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenIPv4, FieldUnknown, "172.23.0.10", false, false},
			Token{TokenLiteral, FieldUnknown, "/", false, false},
			Token{TokenInteger, FieldUnknown, "64048", false, false},
			Token{TokenLiteral, FieldUnknown, "(", false, false},
			Token{TokenIPv4, FieldUnknown, "10.32.0.1", false, false},
			Token{TokenLiteral, FieldUnknown, "/", false, false},
			Token{TokenInteger, FieldUnknown, "52130", false, false},
			Token{TokenLiteral, FieldUnknown, ")", false, false},
		},

		"id=firewall time=\"2005-03-18 14:01:43\" fw=TOPSEC priv=4 recorder=kernel type=conn policy=504 proto=TCP rule=deny src=210.82.121.91 sport=4958 dst=61.229.37.85 dport=23124 smac=00:0b:5f:b2:1d:80 dmac=00:04:c1:8b:d8:82": Sequence{
			Token{TokenLiteral, FieldUnknown, "id", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenString, FieldUnknown, "firewall", false, true},
			Token{TokenLiteral, FieldUnknown, "time", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenLiteral, FieldUnknown, "\"", false, false},
			Token{TokenTS, FieldUnknown, "2005-03-18 14:01:43", false, true},
			Token{TokenLiteral, FieldUnknown, "\"", false, false},
			Token{TokenLiteral, FieldUnknown, "fw", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenString, FieldUnknown, "topsec", false, true},
			Token{TokenLiteral, FieldUnknown, "priv", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenInteger, FieldUnknown, "4", false, true},
			Token{TokenLiteral, FieldUnknown, "recorder", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenString, FieldUnknown, "kernel", false, true},
			Token{TokenLiteral, FieldUnknown, "type", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenString, FieldUnknown, "conn", false, true},
			Token{TokenLiteral, FieldUnknown, "policy", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenInteger, FieldUnknown, "504", false, true},
			Token{TokenLiteral, FieldUnknown, "proto", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenString, FieldUnknown, "tcp", false, true},
			Token{TokenLiteral, FieldUnknown, "rule", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenString, FieldUnknown, "deny", false, true},
			Token{TokenLiteral, FieldUnknown, "src", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenIPv4, FieldUnknown, "210.82.121.91", false, true},
			Token{TokenLiteral, FieldUnknown, "sport", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenInteger, FieldUnknown, "4958", false, true},
			Token{TokenLiteral, FieldUnknown, "dst", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenIPv4, FieldUnknown, "61.229.37.85", false, true},
			Token{TokenLiteral, FieldUnknown, "dport", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenInteger, FieldUnknown, "23124", false, true},
			Token{TokenLiteral, FieldUnknown, "smac", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenMac, FieldUnknown, "00:0b:5f:b2:1d:80", false, true},
			Token{TokenLiteral, FieldUnknown, "dmac", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenMac, FieldUnknown, "00:04:c1:8b:d8:82", false, true},
		},

		"mar 01 09:42:03.875 pffbisvr smtp[2424]: 334 warning: denied access to command 'ehlo vishwakstg1.msn.vishwak.net' from [209.235.210.30]": Sequence{
			Token{TokenTS, FieldUnknown, "mar 01 09:42:03.875", false, false},
			Token{TokenLiteral, FieldUnknown, "pffbisvr", false, false},
			Token{TokenLiteral, FieldUnknown, "smtp", false, false},
			Token{TokenLiteral, FieldUnknown, "[", false, false},
			Token{TokenInteger, FieldUnknown, "2424", false, false},
			Token{TokenLiteral, FieldUnknown, "]", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenInteger, FieldUnknown, "334", false, false},
			Token{TokenLiteral, FieldUnknown, "warning", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenLiteral, FieldUnknown, "denied", false, false},
			Token{TokenLiteral, FieldUnknown, "access", false, false},
			Token{TokenLiteral, FieldUnknown, "to", false, false},
			Token{TokenLiteral, FieldUnknown, "command", false, false},
			Token{TokenLiteral, FieldUnknown, "'", false, false},
			Token{TokenLiteral, FieldUnknown, "ehlo vishwakstg1.msn.vishwak.net", false, false},
			Token{TokenLiteral, FieldUnknown, "'", false, false},
			Token{TokenLiteral, FieldUnknown, "from", false, false},
			Token{TokenLiteral, FieldUnknown, "[", false, false},
			Token{TokenIPv4, FieldUnknown, "209.235.210.30", false, false},
			Token{TokenLiteral, FieldUnknown, "]", false, false},
		},

		"may  2 19:00:02 dlfssrv sendmail[18980]: taa18980: from user daemon: size is 596, class is 0, priority is 30596, and nrcpts=1, message id is <200305021400.taa18980@dlfssrv.in.ibm.com>, relay=daemon@localhost": Sequence{
			Token{TokenTS, FieldUnknown, "may  2 19:00:02", false, false},
			Token{TokenLiteral, FieldUnknown, "dlfssrv", false, false},
			Token{TokenLiteral, FieldUnknown, "sendmail", false, false},
			Token{TokenLiteral, FieldUnknown, "[", false, false},
			Token{TokenInteger, FieldUnknown, "18980", false, false},
			Token{TokenLiteral, FieldUnknown, "]", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenLiteral, FieldUnknown, "taa18980", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenLiteral, FieldUnknown, "from", false, false},
			Token{TokenLiteral, FieldUnknown, "user", false, false},
			Token{TokenLiteral, FieldUnknown, "daemon", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenLiteral, FieldUnknown, "size", false, false},
			Token{TokenLiteral, FieldUnknown, "is", false, false},
			Token{TokenInteger, FieldUnknown, "596", false, false},
			Token{TokenLiteral, FieldUnknown, ",", false, false},
			Token{TokenLiteral, FieldUnknown, "class", false, false},
			Token{TokenLiteral, FieldUnknown, "is", false, false},
			Token{TokenInteger, FieldUnknown, "0", false, false},
			Token{TokenLiteral, FieldUnknown, ",", false, false},
			Token{TokenLiteral, FieldUnknown, "priority", false, false},
			Token{TokenLiteral, FieldUnknown, "is", false, false},
			Token{TokenInteger, FieldUnknown, "30596", false, false},
			Token{TokenLiteral, FieldUnknown, ",", false, false},
			Token{TokenLiteral, FieldUnknown, "and", false, false},
			Token{TokenLiteral, FieldUnknown, "nrcpts", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenInteger, FieldUnknown, "1", false, true},
			Token{TokenLiteral, FieldUnknown, ",", false, false},
			Token{TokenLiteral, FieldUnknown, "message", false, false},
			Token{TokenLiteral, FieldUnknown, "id", false, false},
			Token{TokenLiteral, FieldUnknown, "is", false, false},
			Token{TokenLiteral, FieldUnknown, "<", false, false},
			Token{TokenLiteral, FieldUnknown, "200305021400.taa18980@dlfssrv.in.ibm.com", false, false},
			Token{TokenLiteral, FieldUnknown, ">", false, false},
			Token{TokenLiteral, FieldUnknown, ",", false, false},
			Token{TokenLiteral, FieldUnknown, "relay", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenString, FieldUnknown, "daemon@localhost", false, true},
		},

		"mar 01 09:45:02.596 pffbisvr smtp[2424]: 121 statistics: duration=181.14 user=<egreetings@vishwak.com> id=zduqd sent=1440 rcvd=356 srcif=d45f49a2-b30 src=209.235.210.30/61663 cldst=192.216.179.206/25 svsrc=172.17.74.195/8423 dstif=fd3c875c-064 dst=172.17.74.52/25 op=\"to 1 recips\" arg=<vishwakstg1ojte15fo000033b4@vishwakstg1.msn.vishwak.net> result=\"250 m2004030109385301402 message accepted for delivery\" proto=smtp rule=131 (denied access to command 'ehlo vishwakstg1.msn.vishwak.net' from [209.235.210.30])": Sequence{
			Token{TokenTS, FieldUnknown, "mar 01 09:45:02.596", false, false},
			Token{TokenLiteral, FieldUnknown, "pffbisvr", false, false},
			Token{TokenLiteral, FieldUnknown, "smtp", false, false},
			Token{TokenLiteral, FieldUnknown, "[", false, false},
			Token{TokenInteger, FieldUnknown, "2424", false, false},
			Token{TokenLiteral, FieldUnknown, "]", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenInteger, FieldUnknown, "121", false, false},
			Token{TokenLiteral, FieldUnknown, "statistics", false, false},
			Token{TokenLiteral, FieldUnknown, ":", false, false},
			Token{TokenLiteral, FieldUnknown, "duration", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenFloat, FieldUnknown, "181.14", false, true},
			Token{TokenLiteral, FieldUnknown, "user", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenLiteral, FieldUnknown, "<", false, false},
			Token{TokenString, FieldUnknown, "egreetings@vishwak.com", false, true},
			Token{TokenLiteral, FieldUnknown, ">", false, false},
			Token{TokenLiteral, FieldUnknown, "id", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenString, FieldUnknown, "zduqd", false, true},
			Token{TokenLiteral, FieldUnknown, "sent", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenInteger, FieldUnknown, "1440", false, true},
			Token{TokenLiteral, FieldUnknown, "rcvd", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenInteger, FieldUnknown, "356", false, true},
			Token{TokenLiteral, FieldUnknown, "srcif", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenString, FieldUnknown, "d45f49a2-b30", false, true},
			Token{TokenLiteral, FieldUnknown, "src", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenIPv4, FieldUnknown, "209.235.210.30", false, true},
			Token{TokenLiteral, FieldUnknown, "/", false, false},
			Token{TokenInteger, FieldUnknown, "61663", false, false},
			Token{TokenLiteral, FieldUnknown, "cldst", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenIPv4, FieldUnknown, "192.216.179.206", false, true},
			Token{TokenLiteral, FieldUnknown, "/", false, false},
			Token{TokenInteger, FieldUnknown, "25", false, false},
			Token{TokenLiteral, FieldUnknown, "svsrc", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenIPv4, FieldUnknown, "172.17.74.195", false, true},
			Token{TokenLiteral, FieldUnknown, "/", false, false},
			Token{TokenInteger, FieldUnknown, "8423", false, false},
			Token{TokenLiteral, FieldUnknown, "dstif", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenString, FieldUnknown, "fd3c875c-064", false, true},
			Token{TokenLiteral, FieldUnknown, "dst", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenIPv4, FieldUnknown, "172.17.74.52", false, true},
			Token{TokenLiteral, FieldUnknown, "/", false, false},
			Token{TokenInteger, FieldUnknown, "25", false, false},
			Token{TokenLiteral, FieldUnknown, "op", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenLiteral, FieldUnknown, "\"", false, false},
			Token{TokenString, FieldUnknown, "to", false, true},
			Token{TokenInteger, FieldUnknown, "1", false, false},
			Token{TokenLiteral, FieldUnknown, "recips", false, false},
			Token{TokenLiteral, FieldUnknown, "\"", false, false},
			Token{TokenLiteral, FieldUnknown, "arg", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenLiteral, FieldUnknown, "<", false, false},
			Token{TokenString, FieldUnknown, "vishwakstg1ojte15fo000033b4@vishwakstg1.msn.vishwak.net", false, true},
			Token{TokenLiteral, FieldUnknown, ">", false, false},
			Token{TokenLiteral, FieldUnknown, "result", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenLiteral, FieldUnknown, "\"", false, false},
			Token{TokenInteger, FieldUnknown, "250", false, true},
			Token{TokenLiteral, FieldUnknown, "m2004030109385301402", false, false},
			Token{TokenLiteral, FieldUnknown, "message", false, false},
			Token{TokenLiteral, FieldUnknown, "accepted", false, false},
			Token{TokenLiteral, FieldUnknown, "for", false, false},
			Token{TokenLiteral, FieldUnknown, "delivery", false, false},
			Token{TokenLiteral, FieldUnknown, "\"", false, false},
			Token{TokenLiteral, FieldUnknown, "proto", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenString, FieldUnknown, "smtp", false, true},
			Token{TokenLiteral, FieldUnknown, "rule", true, false},
			Token{TokenLiteral, FieldUnknown, "=", false, false},
			Token{TokenInteger, FieldUnknown, "131", false, true},
			Token{TokenLiteral, FieldUnknown, "(", false, false},
			Token{TokenLiteral, FieldUnknown, "denied", false, false},
			Token{TokenLiteral, FieldUnknown, "access", false, false},
			Token{TokenLiteral, FieldUnknown, "to", false, false},
			Token{TokenLiteral, FieldUnknown, "command", false, false},
			Token{TokenLiteral, FieldUnknown, "'", false, false},
			Token{TokenLiteral, FieldUnknown, "ehlo vishwakstg1.msn.vishwak.net", false, false},
			Token{TokenLiteral, FieldUnknown, "'", false, false},
			Token{TokenLiteral, FieldUnknown, "from", false, false},
			Token{TokenLiteral, FieldUnknown, "[", false, false},
			Token{TokenIPv4, FieldUnknown, "209.235.210.30", false, false},
			Token{TokenLiteral, FieldUnknown, "]", false, false},
			Token{TokenLiteral, FieldUnknown, ")", false, false},
		},
	}
)

func TestMessageScan(t *testing.T) {
	msg := &message{}

	for line, tokens := range messages {
		msg.data = line

		err := msg.tokenize()
		assert.NoError(t, true, err)
		assert.Equal(t, true, tokens, msg.tokens)
	}
}
