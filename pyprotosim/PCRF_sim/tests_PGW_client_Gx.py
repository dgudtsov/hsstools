#!/usr/bin/env python
###############################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
#               2014, PGW client tests are added by L.Belov <lavrbel@gmail.com>
# 		February 2012 - March 2014
# 		Version 0.1.0, Last change on Mar 12, 2014
# 		This software is distributed under the terms of BSD license.    
###############################################################################

## FLOWS AND DESCRIPTION:

## Capabilities Exchange:

#1) PGW ---> CER -----> PCRF
#2) PGW <--- CEA <----- PCRF

## CCR Initial to PCRF, PCRF checks user is valid in SPR DB 
## and reply with PCC Charging-Install Rule and QoS profile settings

#3) PGW ---> CCR-I ---> PCRF
#4)                     PCRF ---> SPR
#5) PGW <--- CCA-I <--  PCRF <--- SPR (PCC rule)

## CCR Update to PCRF, PCRF checks user is valid in SPR DB 
## and reply with PCC Charging-Install Rule and QoS profile settings


#6) PGW ---> CCR-U ---> PCRF ---> SPR
#7)                     PCRF <--- SPR (PCC rule)
#8) PGW <--- CCA-U <--- PCRF

## CCR Terminate to PCRF, PCRF terminates and reply with 2001 Success 

#9) PGW ---> CCR-T ---> PCRF

## Device-Watchdog Request to PCRF and 2001 Success Answer

#10) PGW ----> DWR ----> PCRF
#11) PGW <---- DWA <---- PCRF

## Disconnect Pear Request to PCRF and 2001 Success Answer

#12) PGW ---> DPR ----> PCRF
#13) PGW <--- DPA <---- PCRF

#################################################################
                         

#Next two lines are to include parent directory for testing
import sys, time, os, subprocess
sys.path.append("..")
# Remove them normally

# PGW client - Gx protocol for tests with PCRF simulator

from libDiameter import *

if __name__ == '__main__':

# SET THIS TO YOUR PCRF SIMULATOR IP/PORT

    HOST="127.0.0.1"
    PORT=3868
    ORIGIN_HOST="pgw.myrealm.example"
    ORIGIN_REALM="myrealm.example"
    DEST_REALM="myrealm.example"
    DEST_HOST="pcrf.myrealm.example"
    IDENTITY="1234567890" # This is msisdn of user in SPR DB


    Conn=Connect(HOST,PORT)
    

LoadDictionary("../dictDiameter.xml")


###### FIRST WE CREATE CER and receive CEA ###########################

# Let's build CER
CER_avps=[ ]
CER_avps.append(encodeAVP('Origin-Host', 'pgw.myrealm.example'))
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


print "SLEEP 2 sec"
time.sleep(2)

################## NEXT WE SEND CCR-I AND GET AN ANSWER FROM PCRF ###########################################

CCR_avps=[ ]
CCR_avps.append(encodeAVP('Origin-Host', ORIGIN_HOST))
CCR_avps.append(encodeAVP('Session-Id', 'pgw.myrealm.example;1094791309121_1385989500_428022'))
CCR_avps.append(encodeAVP('Called-Station-Id', 'test.apn'))
CCR_avps.append(encodeAVP('Origin-Realm', ORIGIN_REALM))
CCR_avps.append(encodeAVP('Destination-Realm', DEST_REALM))
CCR_avps.append(encodeAVP('Destination-Host', DEST_HOST))
CCR_avps.append(encodeAVP('Auth-Application-Id', 16777238))
CCR_avps.append(encodeAVP('CC-Request-Type', 1))
CCR_avps.append(encodeAVP('CC-Request-Number', 0))
CCR_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', IDENTITY ), encodeAVP('Subscription-Id-Type', 0)]))
CCR_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', '123456789101112'), encodeAVP('Subscription-Id-Type', 1)]))
CCR_avps.append(encodeAVP('3GPP-SGSN-Address', '192.168.0.2'))
CCR_avps.append(encodeAVP('3GPP-MS-TimeZone', 'GMT'))
CCR_avps.append(encodeAVP('3GPP-User-Location-Info', 'etwas'))
CCR_avps.append(encodeAVP('QoS-Information', [encodeAVP('APN-Aggregate-Max-Bitrate-UL', '500000000'), encodeAVP('APN-Aggregate-Max-Bitrate-DL', '1000000000')]))
CCR_avps.append(encodeAVP('3GPP-SGSN-MCC-MNC', '12345'))
CCR_avps.append(encodeAVP('Access-Network-Charging-Address', '192.168.0.1'))
# Create message header (empty)
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
print "THE CCA - I ANSWER IS:"
  
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
  #print "RAW AVP",avp
   print "Decoded AVP",decodeAVP(avp)
   print "-"*30
   

print "SLEEP 2 sec"
time.sleep(2)

#################### NOW SEND CCR-U REQUEST TO PCRF AND RECEIVE CCA-U ANSWER#############################################

CCR_avps=[ ]
CCR_avps.append(encodeAVP('Origin-Host', ORIGIN_HOST))
CCR_avps.append(encodeAVP('Session-Id', 'pgw.myrealm.example;1094791309121_1385989500_428022'))
CCR_avps.append(encodeAVP('Called-Station-Id', 'test.apn'))
CCR_avps.append(encodeAVP('Origin-Realm', ORIGIN_REALM))
CCR_avps.append(encodeAVP('Destination-Realm', DEST_REALM))
CCR_avps.append(encodeAVP('Destination-Host', DEST_HOST))
CCR_avps.append(encodeAVP('Auth-Application-Id', 16777238))
CCR_avps.append(encodeAVP('CC-Request-Type', 2))
CCR_avps.append(encodeAVP('CC-Request-Number', 1))
CCR_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', IDENTITY ), encodeAVP('Subscription-Id-Type', 0)]))
CCR_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', '123456789101112'), encodeAVP('Subscription-Id-Type', 1)]))
CCR_avps.append(encodeAVP('3GPP-SGSN-Address', '192.168.0.2'))
CCR_avps.append(encodeAVP('3GPP-MS-TimeZone', 'GMT'))
CCR_avps.append(encodeAVP('3GPP-User-Location-Info', 'etwas'))
CCR_avps.append(encodeAVP('QoS-Information', [encodeAVP('APN-Aggregate-Max-Bitrate-UL', '500000000'), encodeAVP('APN-Aggregate-Max-Bitrate-DL', '1000000000')]))
CCR_avps.append(encodeAVP('3GPP-SGSN-MCC-MNC', '12345'))
CCR_avps.append(encodeAVP('Access-Network-Charging-Address', '192.168.0.1'))
# Create message header (empty)
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
print "THE CCA - U ANSWER IS:"
  
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
  #print "RAW AVP",avp
   print "Decoded AVP",decodeAVP(avp)
   print "-"*30

print "SLEEP 2 sec"
time.sleep(2)


#################### NOW SEND CCR-T REQUEST TO PCRF AND RECEIVE CCA-T ANSWER #############################################

CCR_avps=[ ]
CCR_avps.append(encodeAVP('Origin-Host', ORIGIN_HOST))
CCR_avps.append(encodeAVP('Session-Id', 'pgw.myrealm.example;1094791309121_1385989500_428022'))
CCR_avps.append(encodeAVP('Called-Station-Id', 'test.apn'))
CCR_avps.append(encodeAVP('Origin-Realm', ORIGIN_REALM))
CCR_avps.append(encodeAVP('Destination-Realm', DEST_REALM))
CCR_avps.append(encodeAVP('Destination-Host', DEST_HOST))
CCR_avps.append(encodeAVP('Auth-Application-Id', 16777238))
CCR_avps.append(encodeAVP('CC-Request-Type', 3))
CCR_avps.append(encodeAVP('CC-Request-Number', 2))
CCR_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', IDENTITY ), encodeAVP('Subscription-Id-Type', 0)]))
CCR_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', '123456789101112'), encodeAVP('Subscription-Id-Type', 1)]))
CCR_avps.append(encodeAVP('3GPP-SGSN-Address', '192.168.0.2'))
CCR_avps.append(encodeAVP('3GPP-MS-TimeZone', 'GMT'))
CCR_avps.append(encodeAVP('3GPP-User-Location-Info', 'etwas'))
CCR_avps.append(encodeAVP('QoS-Information', [encodeAVP('APN-Aggregate-Max-Bitrate-UL', '500000000'), encodeAVP('APN-Aggregate-Max-Bitrate-DL', '1000000000')]))
CCR_avps.append(encodeAVP('3GPP-SGSN-MCC-MNC', '12345'))
CCR_avps.append(encodeAVP('Access-Network-Charging-Address', '192.168.0.1'))
# Create message header (empty)
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
print "THE CCA - T ANSWER IS:"
  
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
  #print "RAW AVP",avp
   print "Decoded AVP",decodeAVP(avp)
   print "-"*30

print "SLEEP 2 sec"
time.sleep(2)

################## NOW Watchdog and response ########################

# Let's build DWR
DWR_avps=[ ]
DWR_avps.append(encodeAVP('Origin-Host', 'pgw.myrealm.example'))
DWR_avps.append(encodeAVP('Origin-Realm', 'myrealm.example'))
DWR=HDRItem()
DWR.cmd=dictCOMMANDname2code('Device-Watchdog')
initializeHops(DWR)
msg=createReq(DWR,DWR_avps)
Conn.send(msg.decode('hex'))
# Receive response
received = Conn.recv(1024)
# Parse and display received ANSWER
print "="*30
print "THE DWA ANSWER IS:"

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

print "SLEEP 2 sec"
time.sleep(2)

    
################## NOW DISCONNECT PEER REQUEST #######################


# Let's build DPR
DPR_avps=[ ]
DPR_avps.append(encodeAVP('Origin-Host', 'pgw.myrealm.example'))
DPR_avps.append(encodeAVP('Origin-Realm', 'myrealm.example'))
DPR_avps.append(encodeAVP('Disconnect-Cause', 'DO_NOT_WANT_TO_TALK_TO_YOU')) # tired :)
DPR=HDRItem()
DPR.cmd=dictCOMMANDname2code('Disconnect-Peer')
initializeHops(DPR)
msg=createReq(DPR,DPR_avps)
Conn.send(msg.decode('hex'))
# Receive response
received = Conn.recv(1024)

# Parse and display received ANSWER
print "="*30
print "THE DPA ANSWER IS:"

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


################## Closing connection ##############################

Conn.close()

