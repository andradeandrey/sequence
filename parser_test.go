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
	"testing"

	"github.com/dataence/assert"
)

var (
	samples map[string]string = map[string]string{
		"id=firewall time=\"2005-03-18 14:01:46\" fw=TOPSEC priv=6 recorder=kernel type=conn policy=414 proto=TCP rule=accept src=61.167.71.244 sport=35223 dst=210.82.119.211 dport=25 duration=27 inpkt=37 outpkt=39 sent=1770 rcvd=20926 smac=00:04:c1:8b:d8:82 dmac=00:0b:5f:b2:1d:80": "id = %appname% time = \" %createtime% \" fw = %apphost% priv = %integer% recorder = %string% type = %string% policy = %policyid% proto = %protocol% rule = %status% src = %srcipv4% sport = %srcport% dst = %dstipv4% dport = %dstport% duration = %integer% inpkt = %pktsrecv% outpkt = %pktssent% sent = %bytessent% rcvd = %bytesrecv% smac = %srcmac% dmac = %dstmac%",
		"may  5 18:07:27 dlfssrv unix: dlfs_remove(), entered fname=tempfile":                                                                                                                                                                                                              "%createtime% %apphost% %appname% : %method% ( ) , %string% fname = %string%",
		"may  2 15:51:24 dlfssrv unix: vfs root entry":                                                                                                                                                                                                                                     "%createtime% %apphost% %appname% : vfs root %action%",
		"jan 15 14:07:04 testserver sudo: pam_unix(sudo:auth): conversation failed":                                                                                                                                                                                                        "%createtime% %apphost% %appname% : %method% ( %string% : %action% ) : conversation %status%",
		"jan 15 14:07:04 testserver sudo: pam_unix(sudo:auth): password failed":                                                                                                                                                                                                            "%createtime% %apphost% %appname% : %method% ( %string% : %action% ) : %string% %status%",
		"jan 15 14:07:35 testserver passwd: pam_unix(passwd:chauthtok): password changed for parstream":                                                                                                                                                                                    "%createtime% %apphost% %appname% : %method% ( %string% : %action% ) : password changed for %dstuser%",
		"jan 14 10:15:56 testserver sudo:    raghu : tty=pts/3 ; pwd=/home/raghu ; user=root ; command=/bin/su - parstream":                                                                                                                                                                "%createtime% %apphost% %appname% : %srcuser% : tty = %string% ; pwd = %string% ; user = %dstuser% ; command = %method-10%",
		"jan 15 19:15:55 jlz sshd[7106]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=188.65.16.110":                                                                                                                                            "%createtime% %apphost% %appname% [ %sessionid% ] : %string% ( sshd : %string% ) : authentication %status% ; logname = %string% = %integer% euid = %integer% tty = %string% ruser = rhost = %srcipv4%",
		"jan 15 19:25:56 jlz sshd[7774]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=stat.atomsib.net":                                                                                                                                         "%createtime% %apphost% %appname% [ %sessionid% ] : %string% ( sshd : %string% ) : authentication %status% ; logname = %string% = %integer% euid = %integer% tty = %string% ruser = rhost = %srchost%",
	}
)

func TestParserMatchPatterns(t *testing.T) {
	parser := NewParser()
	msg := &message{}

	for _, pat := range samples {
		msg.data = pat
		err := msg.tokenize()
		assert.NoError(t, true, err)
		parser.Add(msg.tokens)
	}

	for data, pat := range samples {
		msg.data = data
		err := msg.tokenize()
		assert.NoError(t, true, err)

		seq, err := parser.Parse(msg.tokens)
		assert.NoError(t, true, err)
		assert.Equal(t, true, pat, seq.String())
	}
}
