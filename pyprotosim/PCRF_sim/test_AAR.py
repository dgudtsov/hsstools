#!/usr/bin/python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - March 2014
# Version 0.2.9, Last change on Mar 06, 2014
# This software is distributed under the terms of BSD license.    
##################################################################

# Example of AAR request (Rx) from AF to PCRF

#Next two lines are to include parent directory for testing
import sys
sys.path.append("..")

#

from libDiameter import *


if __name__ == '__main__':
    HOST='127.0.0.1'
    PORT=3868


Conn=Connect(HOST,PORT)

LoadDictionary("../dictDiameter.xml")


# 3GPP AAR AVPs:

#<AA-Request> ::= < Diameter Header: 265, REQ, PXY >
#< Session-Id >
#{ Auth-Application-Id }
#{ Origin-Host }
#{ Origin-Realm }
#{ Destination-Realm }
#[ Destination-Host ]
#[ AF-Application-Identifier ]
#[Service-Info-Status ]
#[ AF-Charging-Identifier ]
#[ SIP-Forking-Indication ]
#[ Reservation-Priority ]
#[ Framed-IP-Address ]
#[ Framed-IPv6-Prefix ]
#[ Called-Station-ID ]
#[ Service-URN ]
#[ Origin-State-Id ]


# Let's build AAR
AAR_avps=[ ]
AAR_avps.append(encodeAVP('Origin-Host', 'vmclient.myrealm.example'))
AAR_avps.append(encodeAVP('Session-Id', 'vmclient.myrealm.example;1094791309121_1385989500_428022'))
AAR_avps.append(encodeAVP('Origin-Realm', 'myrealm.example'))
AAR_avps.append(encodeAVP('Vendor-Id', 11111))
AAR_avps.append(encodeAVP('Product-Name', 'AF'))
AAR_avps.append(encodeAVP('Supported-Vendor-Id', 0))
AAR_avps.append(encodeAVP('Supported-Vendor-Id', 10415))
AAR_avps.append(encodeAVP('Supported-Vendor-Id', 11112))
AAR_avps.append(encodeAVP('Auth-Application-Id', 16777236)) # This is Rx
AAR_avps.append(encodeAVP('Called-Station-Id', 'test.apn'))
AAR_avps.append(encodeAVP('Destination-Realm', 'myrealm.example'))
AAR_avps.append(encodeAVP('Destination-Host', 'pcrf.myrealm.example'))
AAR_avps.append(encodeAVP('Framed-IP-Address', '192.168.0.1'))

# Create message header (empty)
AAR=HDRItem()
# Set command code
AAR.cmd=dictCOMMANDname2code('AA')
# Set Hop-by-Hop and End-to-End
initializeHops(AAR)
# Add AVPs to header and calculate remaining fields
msg=createReq(AAR,AAR_avps)
# msg now contains AAR Request as hex string

# send data
Conn.send(msg.decode('hex'))
# Receive response
received = Conn.recv(1024)

# Parse and display received AAA ANSWER
print "="*30
print "THE AAA ANSWER IS:"

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

