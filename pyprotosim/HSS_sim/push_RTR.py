#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - November 2012
# Version 0.3.1, Last change on Nov 09, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

#Next two lines are to include parent directory for testing
import sys
sys.path.append("..")
# Remove them normally

# HSS server - trigger RTR request to client

from libDiameter import *
import datetime
import time

def create_RTR():
    # Let's build Registration-Termination Request
    REQ_avps=[]
    REQ_avps.append(encodeAVP("Session-Id", SESSION_ID))
    REQ_avps.append(encodeAVP("Auth-Application-Id",APPLICATION_ID))
    REQ_avps.append(encodeAVP("Auth-Session-State", 1)) # 1 - NO_STATE_MAINTAINED
    REQ_avps.append(encodeAVP("SIP-Deregistration-Reason", 1)) # 1 - NO_STATE_MAINTAINED
    REQ_avps.append(encodeAVP("User-Name", IDENTITY)) 
    # Create message header (empty)
    REQ=HDRItem()
    # Set command code
    REQ.cmd=dictCOMMANDname2code("Registration-Termination")
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
    ################
    HOST=""
    PORT=3869
    IDENTITY="262022503508143"                        
    # 3GPP  SWx=16777265  STa=16777250  S6b=16777272  Wx=16777219
    APPLICATION_ID=16777250
    # Let's assume that my Diameter messages will fit into 4k
    MSG_SIZE=4096
    # Connect to server
    Conn=Connect(HOST,PORT)
    ###########################################################
    SESSION_ID=create_Session_Id()
    msg=create_RTR()
    # msg now contains STR as hex string
    logging.debug("+"*30)
    # send data
    Conn.send(msg.decode("hex"))
    # Receive response
    received = Conn.recv(MSG_SIZE)
    ###########################################################
    # And close the connection
    Conn.close()

