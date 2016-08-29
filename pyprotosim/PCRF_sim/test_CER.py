#!/usr/bin/python

##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - March 2012
# Version 0.1.0, Last change on Mar 06, 2014
# This software is distributed under the terms of BSD license.    
##################################################################


#Next two lines are to include parent directory for testing
import sys
sys.path.append("..")


from libDiameter import *


if __name__ == '__main__':
    HOST='127.0.0.1'
    PORT=3868


Conn=Connect(HOST,PORT)

LoadDictionary("../dictDiameter.xml")

# Let's build CER
CER_avps=[ ]
CER_avps.append(encodeAVP('Origin-Host', 'vmclient.myrealm.example'))
CER_avps.append(encodeAVP('Origin-Realm', 'myrealm.example'))
CER_avps.append(encodeAVP('Vendor-Id', 11111))
CER_avps.append(encodeAVP('Product-Name', 'PCEF'))
CER_avps.append(encodeAVP('Supported-Vendor-Id', 0))
CER_avps.append(encodeAVP('Supported-Vendor-Id', 10415))
CER_avps.append(encodeAVP('Supported-Vendor-Id', 11111))
CER_avps.append(encodeAVP('Auth-Application-Id', 16777238))
# Create message header (empty)
CER=HDRItem()
# Set command code
CER.cmd=dictCOMMANDname2code('Capabilities-Exchange')
# Set Hop-by-Hop and End-to-End
initializeHops(CER)
# Add AVPs to header and calculate remaining fields
msg=createReq(CER,CER_avps)
# msg now contains CER Request as hex string

# send data
Conn.send(msg.decode('hex'))
# Receive response
received = Conn.recv(1024)

# Parse and display received CEA ANSWER
print "="*30
print "THE CEA ANSWER IS:"

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

