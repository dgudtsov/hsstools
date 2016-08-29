#!/usr/bin/python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# Test client added by L.Belov <lavrbel@gmail.com>
# February 2012 - March 2014
# Version 0.1.1, Last change on Mar 11, 2014
# This software is distributed under the terms of BSD license.    
##################################################################

#Next two lines are to include parent directory for testing

import sys
sys.path.append("..")

# THIS TEST WILL SEND RAR-T MESSAGE TO PCRF server (IP_ADDR_PCRF:3869)
# WHICH WILL SEND RAR-T request to PCEF client 
# YOUR PCEF CLIENT MUST BE CONNECTED TO PCRF SIMULATOR BEFORE YOU SEND RAR-T
# YOU NEED TO CHANGE PROPER SESSION ID AND MSISDN BELOW 


from libDiameter import *

import datetime
import time


def create_RAR():
    
    # Let's build RAR-T
    RAR_avps=[ ]
    RAR_avps.append(encodeAVP('Session-Id', str(SESSION_ID)))
    RAR_avps.append(encodeAVP('Product-Name', 'PCRF'))
    RAR_avps.append(encodeAVP('Supported-Vendor-Id', 0))
    RAR_avps.append(encodeAVP('Supported-Vendor-Id', 10415))
    RAR_avps.append(encodeAVP('Supported-Vendor-Id', 11111))
    RAR_avps.append(encodeAVP('Auth-Application-Id', 16777238))
    RAR_avps.append(encodeAVP('Destination-Realm', 'myrealm.example'))
    RAR_avps.append(encodeAVP('Destination-Host', 'vmclient.myrealm.example'))
    RAR_avps.append(encodeAVP('Re-Auth-Request-Type', 0))
    RAR_avps.append(encodeAVP('Session-Release-Cause', 'UNSPECIFIED_REASON'))
    
    # Create message header (empty)
    RAR=HDRItem()
    # Set command code
    RAR.cmd=dictCOMMANDname2code("Re-Auth")
    # Set Application-Id
    RAR.appId=16777238
    # Set Hop-by-Hop and End-to-End
    initializeHops(RAR)
    # Set Proxyable flag
    setFlags(RAR,DIAMETER_HDR_PROXIABLE)
    # Add AVPs to header and calculate remaining fields
    msg=createReq(RAR,RAR_avps)
    # msg now contains RAR Request as hex string
    return msg


 
if __name__ == "__main__":
    
    #logging.basicConfig(level=logging.DEBUG)
    LoadDictionary("../dictDiameter.xml")
    ################

    # THIS IS IP AND PORT OF PCRF SERVER WHICH LISTENS COMMANDS FROM YOU.
    # DON'T CHANGE THIS PORT TO 3868 WHERE PCRF SERVER IS CONNECTED FROM PCEF CLIENT !
    
    HOST="127.0.0.1"
    PORT=3869                       
    
    # Change IDENTITY to your msisdn
    
    IDENTITY='1234567891'                        
    APPLICATION_ID=4
    
    # SET HERE YOUR CLIENT'S SESSION ID TO THE ONE INITIATED BY PCEF AND SENT WITH CCR-I request:
    
    SESSION_ID='example_session-id;123455555567787687687687'
    
    # Let's assume that my Diameter messages will fit into 4k
    MSG_SIZE=4096
    # Connect to server
    Conn=Connect(HOST,PORT)
    ###########################################################
  
    msg=create_RAR()
    # msg now contains STR as hex string
    logging.debug("+"*30)
    # send data
    Conn.send(msg.decode("hex"))
    # Receive response
    received = Conn.recv(MSG_SIZE)
    print "Received RAR",received.encode("hex")

    ###########################################################
    # And close the connection
    Conn.close()

