#!/usr/bin/python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - March 2014
# Version 0.1.1, Last change on Mar 06, 2014
# This software is distributed under the terms of BSD license.    
##################################################################

#Next two lines are to include parent directory for testing

import sys
sys.path.append("..")

from libDiameter import *

if __name__ == '__main__':

# SET PCRF SERVER SIMULATOR IP/PORT THERE

 HOST='127.0.0.1'
 PORT=3868


Conn=Connect(HOST,PORT)

LoadDictionary("../dictDiameter.xml")

# Let's build DPR
DPR_avps=[ ]
DPR_avps.append(encodeAVP('Origin-Host', 'vmclient.myrealm.example'))
DPR_avps.append(encodeAVP('Origin-Realm', 'myrealm.example'))
DPR_avps.append(encodeAVP('Disconnect-Cause', 'DO_NOT_WANT_TO_TALK_TO_YOU'))
DPR=HDRItem()
DPR.cmd=dictCOMMANDname2code('Disconnect-Peer')
initializeHops(DPR)
msg=createReq(DPR,DPR_avps)
Conn.send(msg.decode('hex'))
# Receive response
received = Conn.recv(1024)

# Parse and display received ANSWER
print "="*30
print "THE ANSWER IS:"

msg=received.encode('hex')
print "="*30
H=HDRItem()
stripHdr(H,msg)
avps=splitMsgAVPs(H.msg)
cmd=dictCOMMANDcode2name(H.flags,H.cmd)
if cmd==ERROR:
 print 'Unknown command',H.cmd
else:
 print cmd
 print "Hop-by-Hop=",H.HopByHop,"End-to-End=",H.EndToEnd,"ApplicationId=",H.appId
 print "="*30
 for avp in avps:
#   print "RAW AVP",avp
    print "Decoded AVP",decodeAVP(avp)
    print "-"*30    

# END OF TEST

