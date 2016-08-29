#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - March 2012
# Version 0.2.6, Last change on Mar 20, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

#Next two lines are to include parent directory for testing
import sys
sys.path.append("..")
# Remove them normally

# HSS client - MAR/MAA for diameter EAP-AKA client

from libDiameter import *
import eap
import datetime
import time

def create_CER():
    # Let's build CER
    CER_avps=[]
    CER_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    CER_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    CER_avps.append(encodeAVP("Vendor-Id", 28458))
    CER_avps.append(encodeAVP("Origin-State-Id", 1))
    CER_avps.append(encodeAVP("Supported-Vendor-Id", 10415))
    CER_avps.append(encodeAVP("Auth-Application-Id", 0xFFFFFFFF))
    CER_avps.append(encodeAVP("Acct-Application-Id", 0xFFFFFFFF))
    # Create message header (empty)
    CER=HDRItem()
    # Set command code
    CER.cmd=dictCOMMANDname2code("Capabilities-Exchange")
    # Set Hop-by-Hop and End-to-End
    initializeHops(CER)
    # Add AVPs to header and calculate remaining fields
    msg=createReq(CER,CER_avps)
    # msg now contains CER Request as hex string
    return msg
       
def create_MAR(ETYPE):
    # Let's build Multimedia AuthRequest
    REQ_avps=[]
    # Grouped AVPs are encoded like this
    REQ_avps.append(encodeAVP("Vendor-Specific-Application-Id",[
         encodeAVP("Vendor-Id",dictVENDORid2code('TGPP')),
        encodeAVP("Auth-Application-Id",APPLICATION_ID)]))    
    REQ_avps.append(encodeAVP("User-Name", IDENTITY))
    REQ_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    REQ_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    REQ_avps.append(encodeAVP("Destination-Realm", DEST_REALM))
    REQ_avps.append(encodeAVP("Auth-Session-State", 1))    
    if ETYPE=="EAP-SIM":
        REQ_avps.append(encodeAVP("NAS-Port-Type",5))
        # For EAP-SIM
        REQ_avps.append(encodeAVP("SIP-Number-Auth-Items", 3))
        REQ_avps.append(encodeAVP("SIP-Auth-Data-Item",[
            encodeAVP("Authentication-Method",0)]))
    else:
        REQ_avps.append(encodeAVP("Session-Id", SESSION_ID))
        REQ_avps.append(encodeAVP("RAT-Type", 0))
        REQ_avps.append(encodeAVP("ANID", "HRPD"))
        REQ_avps.append(encodeAVP("Destination-Host", DEST_HOST))
        # For EAP-AKA and EAP-AKA'
        REQ_avps.append(encodeAVP("SIP-Number-Auth-Items", 1))
        REQ_avps.append(encodeAVP("SIP-Auth-Data-Item",[
            encodeAVP("SIP-Authentication-Scheme",ETYPE)]))
    # Create message header (empty)
    REQ=HDRItem()
    # Set command code
    REQ.cmd=dictCOMMANDname2code("Multimedia-Auth")
    # Set Application-Id
    REQ.appId=APPLICATION_ID
    # Set Hop-by-Hop and End-to-End
    initializeHops(REQ)
    # Set Proxyable flag
    setFlags(REQ,DIAMETER_HDR_PROXIABLE)
    # Add AVPs to header and calculate remaining fields
    msg=createReq(REQ,REQ_avps)
    # msg now contains MAR Request as hex string
    return msg
   
def create_Session_Id():
    #The Session-Id MUST be globally and eternally unique
    #<DiameterIdentity>;<high 32 bits>;<low 32 bits>[;<optional value>]
    now=datetime.datetime.now()
    ret=ORIGIN_HOST+";"
    ret=ret+str(now.year)[2:4]+"%02d"%now.month+"%02d"%now.day
    ret=ret+"%02d"%now.hour+"%02d"%now.minute+";"
    ret=ret+"%02d"%now.second+str(now.microsecond)+";"
    ret=ret+IDENTITY[2:16]
    return ret
 
if __name__ == "__main__":
    #logging.basicConfig(level=logging.DEBUG)
    LoadDictionary("../dictDiameter.xml")
    eap.LoadEAPDictionary("../dictEAP.xml")
    ################
    HOST="172.31.112.33"
    PORT=3868
    ORIGIN_HOST="client.test.com"
    ORIGIN_REALM="test.com"
    IDENTITY="262022503508143"                        
    #ETYPE="EAP-SIM"
    ETYPE="EAP-AKA"
    #ETYPE="EAP-AKA'"
    if ETYPE=="EAP-SIM":
    # 3GPP  SWx=16777265  STa=16777250  S6b=16777272  Wx=16777219
        APPLICATION_ID=16777219
    else:
        APPLICATION_ID=16777265                
    # Let's assume that my Diameter messages will fit into 4k
    MSG_SIZE=4096
    # Connect to server
    Conn=Connect(HOST,PORT)
    ###########################################################
    # Let's build CER
    msg=create_CER()
    # msg now contains CER Request as hex string
    logging.debug("+"*30)
    # send data
    Conn.send(msg.decode("hex"))
    # Receive response
    received = Conn.recv(MSG_SIZE)
    # split header and AVPs
    CEA=HDRItem()
    stripHdr(CEA,received.encode("hex"))
    # From CEA we needed Destination-Host and Destination-Realm
    Capabilities_avps=splitMsgAVPs(CEA.msg)
    print Capabilities_avps
    DEST_HOST=findAVP("Origin-Host",Capabilities_avps)
    DEST_REALM=findAVP("Origin-Realm",Capabilities_avps)
    ###########################################################
    SESSION_ID=create_Session_Id()
    msg=create_MAR(ETYPE)
    # msg now contains MAR as hex string
    logging.debug("+"*30)
    # send data
    Conn.send(msg.decode("hex"))
    # Receive response
    received = Conn.recv(MSG_SIZE)
    ###########################################################
    # And close the connection
    Conn.close()

