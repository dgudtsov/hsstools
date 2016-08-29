#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.3.1 Last change at Nov 17, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# Dummy tests for manual verification

#Next two lines are to include parent directory for testing
import sys
sys.path.append("..")
# Remove them normally

# Testing handling basic AVP types
from libDiameter import *

def CreateMSG():
    AVP=[]
    # Int32
    AVP.append(encodeAVP("Error-Cause",1025))
    # Int64
    AVP.append(encodeAVP("Value-Digits",12345))
    # Unsigned32
    AVP.append(encodeAVP("NAS-Port",2345))
    # Unsigned64
    AVP.append(encodeAVP("Framed-Interface-Id",2345))
    # Float32
    AVP.append(encodeAVP("Token-Rate",12.34))
    # Float64
    AVP.append(encodeAVP("SCAP-Cost",12.34))
    # IP Address v4 
    AVP.append(encodeAVP("Host-IP-Address","172.30.211.2"))
    # IP Address v6
    AVP.append(encodeAVP("Host-IP-Address","::ffff:d9c8:4cca"))
    # OctetString
    AVP.append(encodeAVP("User-Password","teststr"))
    # UTF8 String 
    textUTF8 = u'pi: \u03c0'
    #70 69 3a 20 cf 80
    AVP.append(encodeAVP("User-Name",textUTF))
    # Grouped
    AVP.append(encodeAVP("Non-3GPP-User-Data", [
            encodeAVP("Subscription-Id", [
                encodeAVP("Subscription-Id-Data", "123456789"),
                encodeAVP("Subscription-Id-Type", 0)]), 
            encodeAVP("Non-3GPP-IP-Access", 0),
            encodeAVP("Non-3GPP-IP-Access-APN", 0),
            encodeAVP("MIP6-Feature-Vector", 1),
            encodeAVP("APN-Configuration", [
                encodeAVP("Context-Identifier", 1), 
                encodeAVP("Service-Selection", "a1"), 
                encodeAVP("PDN-Type", 0), 
                encodeAVP("AMBR", [
                    encodeAVP("Max-Requested-Bandwidth-UL", 500), 
                    encodeAVP("Max-Requested-Bandwidth-DL", 500)]), 
                encodeAVP("EPS-Subscribed-QoS-Profile", [
                    encodeAVP("QoS-Class-Identifier", 1), 
                    encodeAVP("Allocation-Retention-Priority", [
                        encodeAVP("Priority-Level", 0)])])]),
            encodeAVP("Context-Identifier", 0)]))
    # Time
    # Nov 17, 2012, 10:30:00 GMT +1
    unixtime=date2epoch(2012,11,17,10,30,00)
    AVP.append(encodeAVP("Event-Timestamp",unixtime))
    # Enumerated name replacement
    AVP.append(encodeAVP("Service-Type","Framed"))
    AVP.append(encodeAVP("Service-Type",2))
    # IP v4 
    AVP.append(encodeAVP("Framed-IP-Address","172.30.211.2"))
    # IP v6
    AVP.append(encodeAVP("Framed-IP-Address","::ffff:d9c8:4cca"))
    # Create message header (empty)
    CER=HDRItem()
    # Set command code
    CER.cmd=dictCOMMANDname2code("Capabilities-Exchange")
    # Set Hop-by-Hop and End-to-End
    initializeHops(CER)
    # Add AVPs to header and calculate remaining fields
    msg=createReq(CER,AVP)
    # msg now contains CER Request as hex string
    return msg

def DecodeMSG(msg):
    H=HDRItem()
    stripHdr(H,msg)
    avps=splitMsgAVPs(H.msg)
    cmd=dictCOMMANDcode2name(H.flags,H.cmd)
    if cmd==ERROR:
        print 'Unknown command',H.cmd
    else:
        print cmd
    print "Hop-by-Hop=",H.HopByHop,"End-to-End=",H.EndToEnd,"ApplicationId=",H.appId
    for avp in avps:
      print "RAW AVP",avp
      print "Decoded AVP",decodeAVP(avp)
    print "-"*30                
    

if __name__ == "__main__":
    #logging.basicConfig(level=logging.DEBUG)
    #logging.basicConfig(level=logging.INFO)
    LoadDictionary("../dictDiameter.xml")

    msg=CreateMSG()
    print msg
    print "="*30
    try:
        # Fire to test server for verification with wireshark
        # I use dummy-server.py
        HOST="192.168.89.129"
        PORT=8889
        # Connect to server
        Conn=Connect(HOST,PORT)
        # send data
        Conn.send(msg.decode("hex"))
        Conn.close()
    except:
        pass
    DecodeMSG(msg)


######################################################        
# History
# Ver 0.2.6 - Mar 18, 2012 - initial version
# Ver 0.2.8 - May 12, 2012 - Grouped, Float
# Ver 0.3.1 - Nov 17, 2012 - Time, IPv6, enum named support
#           - Nov 19, 2012 - wireshark verification added               
                

