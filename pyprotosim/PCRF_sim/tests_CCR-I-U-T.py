#!/usr/bin/python

##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# Test client added by L.Belov <lavrbel@gmail.com>
# February 2012 - March 2014
# Version 0.1.1, Last change on Mar 11, 2014
# This software is distributed under the terms of BSD license.    
##################################################################

# These are 5 CCR tests for using with and without LDAP database. 

#Next two lines are to include parent directory for testing
import sys
import socket
sys.path.append("..")

from libDiameter import *

if __name__ == '__main__':

# SET THIS TO PCRF SIMULATOR IP/PORT
    HOST='127.0.0.1'
    PORT=3868


    Conn=Connect(HOST,PORT)

LoadDictionary("../dictDiameter.xml")

# TEST 1 -- SEND CCR-I TO PCRF with MSISDN FOUND in SPR database
print "TEST 1 -- SEND CCR-I TO PCRF with IDENTITY(MSISDN) WHICH IS FOUND in SPR LDAP database"

CCR_avps=[ ]
CCR_avps.append(encodeAVP('Origin-Host', 'pgw.myrealm.example'))
CCR_avps.append(encodeAVP('Session-Id', 'pgw.myrealm.example;1094791309121_1385989500_428022'))
CCR_avps.append(encodeAVP('Called-Station-Id', 'test.apn'))
CCR_avps.append(encodeAVP('Origin-Realm', 'myrealm.example'))
CCR_avps.append(encodeAVP('Destination-Realm', 'myrealm.example'))
CCR_avps.append(encodeAVP('Destination-Host', 'pcrf.myrealm.example'))
CCR_avps.append(encodeAVP('Auth-Application-Id', 16777238))
CCR_avps.append(encodeAVP('CC-Request-Type', 1))
CCR_avps.append(encodeAVP('CC-Request-Number', 0))
CCR_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', '1234567890'), encodeAVP('Subscription-Id-Type', 0)]))
CCR_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', '123456789101112'), encodeAVP('Subscription-Id-Type', 1)]))
CCR_avps.append(encodeAVP('Framed-IP-Address', '192.168.0.1'))

# 3GPP Gx=16777238
# Create message header (empty)
CCR=HDRItem()
# Set command code
CCR.cmd=dictCOMMANDname2code('Credit-Control')
# Set Hop-by-Hop and End-to-End
initializeHops(CCR)
# Add AVPs to header and calculate remaining fields
msg1=createReq(CCR,CCR_avps)
# msg now contains CCR Request as hex string
# send data
Conn.send(msg1.decode('hex'))
# Receive response
received1 = Conn.recv(1024)

# Parse and display received ANSWER
print "="*30
print "THE ANSWER IS:"

msg=received1.encode('hex')
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

# END OF TEST 1

# TEST 2 -- SEND CCR-I TO PCRF with ANOTHER MSISDN FOUND in SPR database
print "TEST 2 -- SEND ANOTHER CCR-I TO PCRF with USER FOUND in SPR database"

CCR_avps=[ ]
CCR_avps.append(encodeAVP('Origin-Host', 'pgw.myrealm.example'))
CCR_avps.append(encodeAVP('Session-Id', 'pgw.myrealm.example;1093791309121_1385989500_4280888'))
CCR_avps.append(encodeAVP('Called-Station-Id', 'test.apn'))
CCR_avps.append(encodeAVP('Origin-Realm', 'myrealm.example'))
CCR_avps.append(encodeAVP('Destination-Realm', 'myrealm.example'))
CCR_avps.append(encodeAVP('Destination-Host', 'pcrf.myrealm.example'))
CCR_avps.append(encodeAVP('Auth-Application-Id', 16777238))
CCR_avps.append(encodeAVP('CC-Request-Type', 1))
CCR_avps.append(encodeAVP('CC-Request-Number', 0))
CCR_avps.append(encodeAVP('Framed-IP-Address', '192.168.0.2'))
CCR_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', '1234567891'), encodeAVP('Subscription-Id-Type', 0)]))
CCR_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', '123456789101113'), encodeAVP('Subscription-Id-Type', 1)]))


# 3GPP Gx=16777238
# Create message header (empty)
CCR=HDRItem()
# Set command code
CCR.cmd=dictCOMMANDname2code('Credit-Control')
# Set Hop-by-Hop and End-to-End
initializeHops(CCR)
# Add AVPs to header and calculate remaining fields
msg1=createReq(CCR,CCR_avps)
# msg now contains CCR Request as hex string
# send data
Conn.send(msg1.decode('hex'))
# Receive response
received1 = Conn.recv(1024)

# Parse and display received ANSWER
print "="*30
print "THE ANSWER IS:"

msg=received1.encode('hex')
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

# END OF TEST 2


# TEST 3 -- SEND CCR-U TO PCRF with USER FOUND in SPR database
print "TEST 3 -- SEND CCR-U TO PCRF with VALID USER FOUND in SPR database"

CCR_avps=[ ]
CCR_avps.append(encodeAVP('Origin-Host', 'pgw.myrealm.example'))
CCR_avps.append(encodeAVP('Session-Id', 'pgw.myrealm.example;1094791309121_1385989500_428022'))
CCR_avps.append(encodeAVP('Called-Station-Id', 'test.apn'))
CCR_avps.append(encodeAVP('Origin-Realm', 'myrealm.example'))
CCR_avps.append(encodeAVP('Destination-Realm', 'myrealm.example'))
CCR_avps.append(encodeAVP('Destination-Host', 'pcrf.myrealm.example'))
CCR_avps.append(encodeAVP('Auth-Application-Id', 16777238))
CCR_avps.append(encodeAVP('CC-Request-Type', 2))
CCR_avps.append(encodeAVP('CC-Request-Number', 0))
CCR_avps.append(encodeAVP('Framed-IP-Address', '192.168.0.1'))
CCR_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', '1234567891'), encodeAVP('Subscription-Id-Type', 0)]))
CCR_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', '123456789101114'), encodeAVP('Subscription-Id-Type', 1)]))


# 3GPP Gx=16777238
# Create message header (empty)
CCR=HDRItem()
# Set command code
CCR.cmd=dictCOMMANDname2code('Credit-Control')
# Set Hop-by-Hop and End-to-End
initializeHops(CCR)
# Add AVPs to header and calculate remaining fields
msg1=createReq(CCR,CCR_avps)
# msg now contains CCR Request as hex string
# send data
Conn.send(msg1.decode('hex'))
# Receive response
received1 = Conn.recv(1024)

# Parse and display received ANSWER
print "="*30
print "THE ANSWER IS:"

msg=received1.encode('hex')
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

# END OF TEST 3


# TEST 4 -- SEND CCR-I TO PCRF when USER IS NOT FOUND in SPR database
print "TEST 4 -- SEND CCR-I TO PCRF with USER NOT FOUND in SPR database"
print "Expect 5003 AVP"

CCR_avps=[ ]
CCR_avps.append(encodeAVP('Origin-Host', 'pgw.myrealm.example'))
CCR_avps.append(encodeAVP('Session-Id', 'pgw.myrealm.example;1093791309121_1385989500_426543'))
CCR_avps.append(encodeAVP('Called-Station-Id', 'test.apn'))
CCR_avps.append(encodeAVP('Origin-Realm', 'myrealm.example'))
CCR_avps.append(encodeAVP('Destination-Realm', 'myrealm.example'))
CCR_avps.append(encodeAVP('Destination-Host', 'pcrf.myrealm.example'))
CCR_avps.append(encodeAVP('Auth-Application-Id', 16777238))
CCR_avps.append(encodeAVP('CC-Request-Type', 1))
CCR_avps.append(encodeAVP('CC-Request-Number', 0))
CCR_avps.append(encodeAVP('Framed-IP-Address', '192.168.0.11'))
# We do not have this user in our SPR database:
CCR_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', '1234567894'), encodeAVP('Subscription-Id-Type', 0)]))
CCR_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', '123456789101115'), encodeAVP('Subscription-Id-Type', 1)]))


# 3GPP Gx=16777238
# Create message header (empty)
CCR=HDRItem()
# Set command code
CCR.cmd=dictCOMMANDname2code('Credit-Control')
# Set Hop-by-Hop and End-to-End
initializeHops(CCR)
# Add AVPs to header and calculate remaining fields
msg1=createReq(CCR,CCR_avps)
# msg now contains CCR Request as hex string
# send data
Conn.send(msg1.decode('hex'))
# Receive response
received1 = Conn.recv(1024)

# Parse and display received ANSWER
print "="*30
print "THE ANSWER IS:"

msg=received1.encode('hex')
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

# END OF TEST 4


# TEST 5 - SEND CCR-T REQUEST FROM CLIENT

print "==========SEND CCR-T request originated from user========="
print "TEST 5 -- SEND CCR-T TO PCRF session termination"

CCR_avps=[ ]
CCR_avps.append(encodeAVP('Origin-Host', 'pgw.myrealm.example'))
CCR_avps.append(encodeAVP('Session-Id', 'pgw.myrealm.example;1094791309121_1385989500_428022'))
CCR_avps.append(encodeAVP('Called-Station-Id', 'test.apn'))
CCR_avps.append(encodeAVP('Origin-Realm', 'myrealm.example'))
CCR_avps.append(encodeAVP('Destination-Realm', 'myrealm.example'))
CCR_avps.append(encodeAVP('Destination-Host', 'pcrf.myrealm.example'))
CCR_avps.append(encodeAVP('Auth-Application-Id', 16777238))
CCR_avps.append(encodeAVP('CC-Request-Type', 3))
CCR_avps.append(encodeAVP('CC-Request-Number', 0))
CCR_avps.append(encodeAVP('Framed-IP-Address', '192.168.0.1'))
CCR_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', '1234567891'), encodeAVP('Subscription-Id-Type', 0)]))
CCR_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', '123456789101114'), encodeAVP('Subscription-Id-Type', 1)]))
CCR=HDRItem()
CCR.cmd=dictCOMMANDname2code('Credit-Control')
initializeHops(CCR)
msg3=createReq(CCR,CCR_avps)
Conn.send(msg3.decode('hex'))
# Receive response
received3 = Conn.recv(1024)

# Parse and display received ANSWER
print "="*30
print "THE ANSWER IS:"

msg=received3.encode('hex')
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

