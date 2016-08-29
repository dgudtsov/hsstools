#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - March 2012
# Version 0.2.7, Last change on May 16, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

#Next two lines are to include parent directory for testing
import sys
sys.path.append("..")
# Remove them normally

# Radius client

from libRadius import *
import datetime
import time

def create_Request():
    # Create message header (empty)
    REQ=HDRItem()
    # Set command code
    REQ.Code=dictCOMMANDname2code("Access-Request")
    REQ.Identifier=1
    REQ.Authenticator=createAuthenticator()
    # Let's build Request 
    REQ_avps=[]
    REQ_avps.append(encodeAVP("Calling-Station-Id", "00381123456"))
    REQ_avps.append(encodeAVP("Called-Station-Id", "mms"))
    REQ_avps.append(encodeAVP("User-Name", "testuser"))
    REQ_avps.append(encodeAVP("User-Password", PwCrypt("mms",REQ.Authenticator,"secret")))
    REQ_avps.append(encodeAVP("NAS-Identifier", "FBG01"))
    REQ_avps.append(encodeAVP("NAS-IP-Address", "1.2.3.4"))
    REQ_avps.append(encodeAVP("NAS-Port-Type", 5))
    REQ_avps.append(encodeAVP("NAS-Port", 6000))
    REQ_avps.append(encodeAVP("Acct-Session-Id", "sessionID"))
    REQ_avps.append(encodeAVP("Acct-Multi-Session-Id", "multisessionID"))
    REQ_avps.append(encodeAVP("Service-Type", 2))
    REQ_avps.append(encodeAVP("Framed-Protocol", 1))
    # Add AVPs to header and calculate remaining fields
    msg=createReq(REQ,REQ_avps)
    # msg now contains Access-Request as hex string
    return msg

if __name__ == "__main__":
    #logging.basicConfig(level=logging.DEBUG)
    logging.basicConfig(level=logging.INFO)
    LoadDictionary("../dictRadius.xml")
    HOST="10.14.5.148"
    PORT=1812
    # Let's assume that my Radius messages will fit into 4k
    MSG_SIZE=4096
    ###########################################################
    Conn=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # socket is in blocking mode, so let's add a timeout
    Conn.settimeout(5)
    ###########################################################  
    # Create Access-Request    
    msg=create_Request()
    # msg now contains Access-Request as hex string
    logging.debug("+"*30)
    print "Access-Request",msg
    # send data
    Conn.sendto(msg.decode("hex"),(HOST,PORT))
    # Receive response
    received = Conn.recv(MSG_SIZE)
    # Process response
    RES=HDRItem()
    stripHdr(RES,received.encode("hex"))
    radius_avps=splitMsgAVPs(RES.msg)
    for avps in radius_avps:
        print decodeAVP(avps)
    #print radius_avps
    # Normally - this is the end.
    ###########################################################
    # And close the connection
    Conn.close()
    
    
######################################################        
# History
# 0.2.8 - May 31, 2017 - Radius initial version
