#!/usr/bin/env python
###############################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
#               2014, PGW client tests are added by L.Belov <lavrbel@gmail.com>
# 		February 2012 - March 2014
# 		Version 0.1.0, Last change on Mar 13, 2014
# 		This software is distributed under the terms of BSD license.    
###############################################################################

## FLOWS AND DESCRIPTION:

## Capabilities Exchange:

#1) PGW ---> CER -----> PCRF
#2) PGW <--- CEA <----- PCRF

## CCR Initial to PCRF, PCRF checks if user is valid in SPR DB 
## and reply with PCC Charging-Install Rule and QoS profile settings 'basic'

#3) PGW ---> CCR-I ---> PCRF
#4)                     PCRF ---> SPR
#5) PGW <--- CCA-I <--  PCRF <--- SPR (PCC rule)

## RAR-U (Update) from PCRF to PGW (Push operation) will be sent using script test_push_RAR-U.py manually or (can be run from script)
## with PCC Charging Remove old 'basic ' QoS profile and setting new PCC Charging-Install Rule and QoS profile settings 'highspeed'
## PGW will reply with RAA 2001 reply


#6) PCRF ---> RAR-U ---> PGW 
                     
#7) PCRF <--- RAA <---   PGW

## User is logged off and now sending CCR-T (Terminate) to PCRF, PCRF terminates and reply with 2001 Success 

#8) PGW ---> CCR-T ---> PCRF

## Disconnect Pear Request to PCRF and 2001 Success Answer and close session

#9)  PGW ---> DPR ----> PCRF
#10) PGW <--- DPA <---- PCRF

#################################################################
                         
#Next two lines are to include parent directory for testing
import sys,subprocess
sys.path.append("..")
# Remove them normally


from libDiameter import *
import datetime
import time


def create_CER():
    # Let's build CER
    CER_avps=[]
    CER_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    CER_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    CER_avps.append(encodeAVP("Vendor-Id", 11111))
    CER_avps.append(encodeAVP("Origin-State-Id", 1))
    CER_avps.append(encodeAVP("Supported-Vendor-Id", 10415))
    CER_avps.append(encodeAVP('Supported-Vendor-Id', 0))
    CER_avps.append(encodeAVP('Supported-Vendor-Id', 10415))
    CER_avps.append(encodeAVP('Supported-Vendor-Id', 11111))
    CER_avps.append(encodeAVP('Auth-Application-Id', 16777238))
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


def create_CCR_I():
    # Let's build Server-AssignmentRequest
    REQ_avps=[]
    REQ_avps.append(encodeAVP("Session-Id", SESSION_ID))
    REQ_avps.append(encodeAVP("Destination-Realm", DEST_REALM))
    REQ_avps.append(encodeAVP("User-Name", IDENTITY)) 
    REQ_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    REQ_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    REQ_avps.append(encodeAVP('CC-Request-Type', 1))
    REQ_avps.append(encodeAVP('CC-Request-Number', 0))
    REQ_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', '1234567890'), encodeAVP('Subscription-Id-Type', 0)]))
    REQ_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', '123456789012345'), encodeAVP('Subscription-Id-Type', 1)]))
    REQ_avps.append(encodeAVP('Framed-IP-Address', '192.168.0.1'))
    # Create message header (empty)
    CCR=HDRItem()
    # Set command code
    CCR.cmd=dictCOMMANDname2code("Credit-Control")
    # Set Application-id
    CCR.appId=APPLICATION_ID
    # Set Hop-by-Hop and End-to-End
    initializeHops(CCR)
    # Set Proxyable flag
    setFlags(CCR,DIAMETER_HDR_PROXIABLE)    
    # Add AVPs to header and calculate remaining fields
    ret=createReq(CCR,REQ_avps)
    # ret now contains CCR Request as hex string
    return ret 

def create_CCR_T():
    # Let's build Server-AssignmentRequest
    REQ_avps=[]
    REQ_avps.append(encodeAVP("Session-Id", SESSION_ID))
    REQ_avps.append(encodeAVP("Destination-Realm", DEST_REALM))
    REQ_avps.append(encodeAVP("User-Name", IDENTITY)) 
    REQ_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    REQ_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    REQ_avps.append(encodeAVP('CC-Request-Type', 3))
    REQ_avps.append(encodeAVP('CC-Request-Number', 1))
    REQ_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', '1234567890'), encodeAVP('Subscription-Id-Type', 0)]))
    REQ_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', '123456789012345'), encodeAVP('Subscription-Id-Type', 1)]))
    REQ_avps.append(encodeAVP('Framed-IP-Address', '192.168.0.1'))
    # Create message header (empty)
    CCR=HDRItem()
    # Set command code
    CCR.cmd=dictCOMMANDname2code("Credit-Control")
    # Set Application-id
    CCR.appId=APPLICATION_ID
    # Set Hop-by-Hop and End-to-End
    initializeHops(CCR)
    # Set Proxyable flag
    setFlags(CCR,DIAMETER_HDR_PROXIABLE)    
    # Add AVPs to header and calculate remaining fields
    ret=createReq(CCR,REQ_avps)
    # ret now contains CCR Request as hex string
    return ret        
    
def create_RAA(H):
    # Let's build Re-Auth Answer   
    # We need Session-Id from Request
    RAR_avps=splitMsgAVPs(H.msg)
    sesID=findAVP("Session-Id",RAR_avps) 
    RAA_avps=[]
    RAA_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    RAA_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    RAA_avps.append(encodeAVP("Session-Id", sesID))
    RAA_avps.append(encodeAVP("Result-Code", 2001))   #DIAMETER_SUCCESS 2001
    RAA_avps.append(encodeAVP('Auth-Application-Id', 16777238))
    RAA_avps.append(encodeAVP('Destination-Realm', 'myrealm.example'))
    RAA_avps.append(encodeAVP('Destination-Host', 'pcrf.myrealm.example'))
    RAA_avps.append(encodeAVP('Re-Auth-Request-Type', 0))
    # Create message header (empty)
    RAA=HDRItem()
    # Set command code
    RAA.cmd=H.cmd
    # Set Application-id
    RAA.appId=H.appId
    # Set Hop-by-Hop and End-to-End from request
    RAA.HopByHop=H.HopByHop
    RAA.EndToEnd=H.EndToEnd
    # Add AVPs to header and calculate remaining fields
    ret=createRes(RAA,RAA_avps)
    # ret now contains RAA Response as hex string
    return ret     

def create_DPR():
    # Let's build DPR
    DPR_avps=[ ]
    DPR_avps.append(encodeAVP('Origin-Host', 'pgw.myrealm.example'))
    DPR_avps.append(encodeAVP('Origin-Realm', 'myrealm.example'))
    DPR_avps.append(encodeAVP('Disconnect-Cause', 'DO_NOT_WANT_TO_TALK_TO_YOU')) # tired :)
    DPR=HDRItem()
    DPR.cmd=dictCOMMANDname2code('Disconnect-Peer')
    initializeHops(DPR)
    # Add AVPs to header and calculate remaining fields
    msg=createReq(DPR,DPR_avps)
    # msg now contains DPR Request as hex string
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
    HOST="127.0.0.1"
    PORT=3868
    ORIGIN_HOST="pgw.myrealm.example"
    ORIGIN_REALM="myrealm.example"
    IDENTITY="1234567890"                        
    APPLICATION_ID=16777238                
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
    
    ###########################################################
    # RECEIVING CEA RESPONSE AND PARSING IT
    ###########################################################
    
    # Receive response
    received = Conn.recv(MSG_SIZE)
    # split header and AVPs
    CEA=HDRItem()
    stripHdr(CEA,received.encode("hex"))
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
    # From CEA we needed Destination-Host and Destination-Realm
    Capabilities_avps=splitMsgAVPs(CEA.msg)
    print Capabilities_avps
    DEST_HOST=findAVP("Origin-Host",Capabilities_avps)
    DEST_REALM=findAVP("Origin-Realm",Capabilities_avps)
    
    #############################################################
    # CREATE SESSION ID FOR NEW REQUESTS
    #############################################################
    
    #SESSION_ID=create_Session_Id()
    SESSION_ID='pgw.myrealm.example;1094791309121_1385989500_428022'
    
    #############################################################
    # CREATE CCR-I AND SEND IT TO PCRF AND PARSE IT
    #############################################################
    
    msg=create_CCR_I()
    # msg now contains CCR as hex string
    logging.debug("+"*30)
    # send data
    Conn.send(msg.decode("hex"))
    # Receive response
    received = Conn.recv(MSG_SIZE)
    
    # split header and AVPs
    CCA=HDRItem()
    stripHdr(CCA,received.encode("hex"))
    print "="*30
    print "THE CCA-I ANSWER IS:"
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
    # From CCA we needed Destination-Host and Destination-Realm
    Capabilities_avps=splitMsgAVPs(CCA.msg)
    #print Capabilities_avps
    DEST_HOST=findAVP("Origin-Host",Capabilities_avps)
    DEST_REALM=findAVP("Origin-Realm",Capabilities_avps)
    
    ###########################################################
    # NOW SEND MANUALLY test_push_RAR-U.py script
    # or include it here within subprocess calling script from shell
    ############################################################
    
    print "NOW WAITING FOR RAR-U REQUESTS"
    print "PLEASE RUN SCRIPT MANUALLY ./test_push_RAR-U.py to continue"

    # On Linux you can include subprocess to call test_push_RAR-U.py from here
    #print "Running RAR-U script :" 
    #subprocess.call("./test_push_RAR-U.py")

 
    ###########################################################
    # RAR SECTION FIRST WE NEED TO SEND RAR-U FROM PCRF TO PGW
    ###########################################################
    # Receive response
    received = Conn.recv(MSG_SIZE)
    #print "Received RAR",received.encode("hex")
    RAR=HDRItem()
    stripHdr(RAR,received.encode("hex"))
    
    print "="*30
    print "THE RAR-U REQUEST IS:"
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
    # From RAR we needed Destination-Host and Destination-Realm
    Capabilities_avps=splitMsgAVPs(RAR.msg)
    #print Capabilities_avps
    DEST_HOST=findAVP("Origin-Host",Capabilities_avps)
    DEST_REALM=findAVP("Origin-Realm",Capabilities_avps)        
    
    ###########################################################
    # Sending RAA 2001 Success to PCRF
    ###########################################################
    
    msg=create_RAA(RAR)
    # msg now contains RAA as hex string
    logging.debug("+"*30)
    # send data
    Conn.send(msg.decode("hex"))
    
    
    ############################################################
    # Sending CCR-T message after user is logged off
    ############################################################
   
    msg=create_CCR_T()
    # msg now contains CCR as hex string
    logging.debug("+"*30)
    # send data
    Conn.send(msg.decode("hex"))
    # Receive response
    received = Conn.recv(MSG_SIZE)
    
    # split header and AVPs
    CCA=HDRItem()
    stripHdr(CCA,received.encode("hex"))
    print "="*30
    print "THE CCA-T ANSWER IS:"
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
    # From CCA we needed Destination-Host and Destination-Realm
    Capabilities_avps=splitMsgAVPs(CCA.msg)
    #print Capabilities_avps
    DEST_HOST=findAVP("Origin-Host",Capabilities_avps)
    DEST_REALM=findAVP("Origin-Realm",Capabilities_avps)        
    
    ############################################################
    # Sending DPR message and closing connection
    ############################################################
    
  # Let's build DPR
    msg=create_DPR()
    # msg now contains CER Request as hex string
    logging.debug("+"*30)
    # send data
    Conn.send(msg.decode("hex"))
    
    ###########################################################
    # RECEIVING DPA RESPONSE AND PARSING IT
    ###########################################################
    
    # Receive response
    received = Conn.recv(MSG_SIZE)
    # split header and AVPs
    DPR=HDRItem()
    stripHdr(DPR,received.encode("hex"))
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
    
    
    # And close the connection
    
    Conn.close()


