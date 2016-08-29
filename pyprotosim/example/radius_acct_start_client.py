#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - March 2014
# Version 0.2.9, Last change on Mar 06, 2014
# This software is distributed under the terms of BSD license.    
##################################################################

# two lines are to include parent directory for testing
import sys
sys.path.append("..")

# Radius client

from libRadius import *
import datetime
import time




def create_Request():
    # Create message header (empty)
    REQ=HDRItem()
    # Set command code
    REQ.Code=dictCOMMANDname2code("Accounting-Request")
    REQ.Identifier=1    
    auth=createZeroAuthenticator()
    
    
    # Let's build Request 
    REQ_avps=[]
    REQ_avps.append(encodeAVP('Acct-Status-Type', '\x00\x00\x00\x01'))
    REQ_avps.append(encodeAVP('User-Name', 'username'))
    REQ_avps.append(encodeAVP('Acct-Authentic', 1))
    REQ_avps.append(encodeAVP('Framed-IP-Address', '127.0.0.1'))
    REQ_avps.append(encodeAVP('Called-Station-Id', 'test.apn'))
    REQ_avps.append(encodeAVP('Calling-Station-Id', '1234567891'))
    REQ_avps.append(encodeAVP('NAS-IP-Address', '192.168.0.1'))
    REQ_avps.append(encodeAVP('NAS-Identifier', '192.168.0.1'))
    REQ_avps.append(encodeAVP('Framed-Protocol', 7))
    REQ_avps.append(encodeAVP('Service-Type', 2))
    REQ_avps.append(encodeAVP('NAS-Port-Type', 5))
    REQ_avps.append(encodeAVP('Acct-Session-Id', 'D4C8F56173c26ae2'))
    REQ_avps.append(encodeAVP('3GPP-IMSI', '111111111111111'))
    REQ_avps.append(encodeAVP('3GPP-IMSI-MCC-MNC', '11111'))
    REQ_avps.append(encodeAVP('3GPP-SGSN-Address', '192.168.0.1'))
    REQ_avps.append(encodeAVP('3GPP-NSAPI', '6'))
    REQ_avps.append(encodeAVP('3GPP-GGSN-MCC-MNC', '11111'))
    REQ_avps.append(encodeAVP('3GPP-Charging-Characteristics', '0400'))
    REQ_avps.append(encodeAVP('3GPP-IMEISV', '111111111111111'))
    REQ_avps.append(encodeAVP('3GPP-User-Location-Info', '\x01"\xf00\x9c\xa7+_'))
    REQ_avps.append(encodeAVP('3GPP-Charging-Id', 1111111111))
    REQ_avps.append(encodeAVP('3GPP-PDP-Type', 0))
    REQ_avps.append(encodeAVP('3GPP-CG-Address', '192.168.0.1'))
    REQ_avps.append(encodeAVP('3GPP-Selection-Mode', '0'))
    REQ_avps.append(encodeAVP('3GPP-Negotiated-DSCP', '\x00'))
    REQ_avps.append(encodeAVP('3GPP-GPRS-QoS-Profile', '05-23921F9396D5FE74800000006400'))
 
    msg=createWithAuthenticator(REQ,auth,REQ_avps,SECRET)
    # msg now contains Accounting-Request as hex string
    return msg

if __name__ == "__main__":
    #logging.basicConfig(level=logging.DEBUG)
    logging.basicConfig(level=logging.INFO)
    LoadDictionary("../dictRadius.xml")
    HOST="127.0.0.1"
    PORT=1813
    SECRET="secret"
    # Let's assume that my Radius messages will fit into 4k
    MSG_SIZE=4096
    ###########################################################
    Conn=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # socket is in blocking mode, so let's add a timeout
    Conn.settimeout(5)
    ###########################################################  
    
    # Create Acconting-Request (Start)    
    msg=create_Request()
    # msg now contains Accounting-Request as hex string
    logging.debug("+"*30)
    print "Accounting-Request",msg
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
# 0.2.9 - Mar 06, 2014 - Radius accounting example added
# 0.2.8 - May 31, 2013 - Radius initial version
