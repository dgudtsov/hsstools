#!/usr/bin/python

##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# Test client added by L.Belov <lavrbel@gmail.com>
# February 2012 - April 2014
# Version 0.1.1, Last change on Mar 11, 2014
# This software is distributed under the terms of BSD license.    
##################################################################

#Next two lines are to include parent directory for testing
import sys
sys.path.append("..")

# THIS TEST WILL SEND RAR-U MESSAGE TO PCRF server (IP_PCRF_SERVER:3869) WHICH WILL
# SEND RAR-U request to PCEF client
# YOUR PCEF CLIENT MUST BE CONNECTED TO PCRF BEFORE YOU SEND RAR-U
# EDIT PROPER VALUES IN SESSION_ID, CHARGING-RULE-NAME
# 

from libDiameter import *

import datetime
import time

 

 

def create_RAR():
     
    sessionid= SESSION_ID
    # Let's build RAR-U
    RAR_avps=[ ]
    RAR_avps.append(encodeAVP('Session-Id', SESSION_ID))
    RAR_avps.append(encodeAVP('Product-Name', 'PCRF'))
    RAR_avps.append(encodeAVP('Supported-Vendor-Id', 0))
    RAR_avps.append(encodeAVP('Supported-Vendor-Id', 10415))
    RAR_avps.append(encodeAVP('Supported-Vendor-Id', 11111))
    RAR_avps.append(encodeAVP('Auth-Application-Id', 16777238))
    RAR_avps.append(encodeAVP('Destination-Realm', 'myrealm.example'))
    RAR_avps.append(encodeAVP('Destination-Host', 'pgw.myrealm.example'))
    RAR_avps.append(encodeAVP('Re-Auth-Request-Type', 0))
    #RAR_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data',IDENTITY), encodeAVP('Subscription-Id-Type', 0)]))
    #RAR_avps.append(encodeAVP('Charging-Rule-Install',[encodeAVP('Charging-Rule-Name', 'activate_service_smtp'), encodeAVP('Charging-Rule-Name', 'set_service_1234_on')]))
    #RAR_avps.append(encodeAVP('Charging-Rule-Remove',[encodeAVP('Charging-Rule-Name', 'activate_service_filter'), encodeAVP('Charging-Rule-Name', 'set_service_14445_off')]))
    RAR_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', IDENTITY), encodeAVP('Subscription-Id-Type', 0)]))
    RAR_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', '123456789012345'), encodeAVP('Subscription-Id-Type', 1)]))
    
    # SENDING RAR-U QoS highspeed profile with different max bitrate and qos settings
    
    # Removing basic profile :
    
    RAR_avps.append(encodeAVP('Charging-Rule-Remove',[encodeAVP('Charging-Rule-Base-Name','basic')]))
    
    # Installing highspeed profile:
    
    RAR_avps.append(encodeAVP('Charging-Rule-Install',[encodeAVP('Charging-Rule-Base-Name','highspeed')]))
    RAR_avps.append(encodeAVP('QoS-Information',[encodeAVP('APN-Aggregate-Max-Bitrate-UL','1000000000'),encodeAVP('APN-Aggregate-Max-Bitrate-DL','2000000000')]))
    RAR_avps.append(encodeAVP('Online',0)) # not yet OCS supported
    RAR_avps.append(encodeAVP('Offline',0)) # not yet OFCS supported
    RAR_avps.append(encodeAVP('Default-EPS-Bearer-QoS',[encodeAVP('QoS-Class-Identifier','QCI_5')]))
    RAR_avps.append(encodeAVP('Allocation-Retention-Priority',[encodeAVP('Priority-Level','5')]))
    
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
    # THIS IS IP AND PORT OF PCRF_SERVER  WHICH LISTENS COMMANDS FROM YOU.
    # DON'T CHANGE THIS PORT TO 3868 WHERE PCRF SERVER IS CONNECTED FROM PCEF client
    # SET HERE YOUR PCRF SIMULATOR IP/PORT:
    
    HOST="127.0.0.1"
    PORT=3869
    IDENTITY="1234567890"                        
    APPLICATION_ID=4
    
    # SET THIS TO YOUR SESSION ID
    SESSION_ID='pgw.myrealm.example;1094791309121_1385989500_428022'
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

