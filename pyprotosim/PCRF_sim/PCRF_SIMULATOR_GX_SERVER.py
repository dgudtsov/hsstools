#!/usr/bin/python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - March 2014
# Version 0.1.1, Last change on Mar 06, 2014
# This software is distributed under the terms of BSD license.    
##################################################################

#####################################################################################
# Simple PCRF GX SIMULATOR server example, v2.0 <lavrbel@gmail.com>
# Will just reply on CCR-I, CCR-U, CCR-T request with CCA-I(U) and one PCC Charging-Install rule
# It will use CCR-I or U messages to extract msisdn and session id and insert them into CCA-I(U) response
# Set your own PCC rule in code below  
# Set your IP address in HOST parameter : e.g HOST = "127.0.0.1"
# This server supports CER,DWR,DPR,CCR-I,CCR-U,CCR-T,RAR-U,RAR-T
# History of changes:
# 06.03.2014 - added AAR/AAA over Rx interface for AF <lavrbel@gmail.com>
# *****************************************************************
# This simulator is based on PyProtosim opensource software which is distributed under 
# the terms of BSD license.
# Please check the website for PyProtosim software and copyrights here:
# http://sourceforge.net/projects/pyprotosim/
######################################################################################


# PCRF Simulator Gx build upon libDiameter's PyProtosim software
# interrupt the program with Ctrl-C


#Next two lines include parent directory where libDiameter is located

import sys
sys.path.append("..")

# Remove them if everything is in the same dir



import socket
import select
import logging
from libDiameter import *

SKIP=0

def handle_PCRF(conn):
    global sock_list
    # conn is the TCP socket connected to the client
    dbg="Connection:",conn.getpeername(),'to',conn.getsockname()
    logging.info(dbg)
    #get input ,wait if no data
    data=conn.recv(BUFFER_SIZE)
    #suspect more data (try to get it all without stopping if no data)
    if (len(data)==BUFFER_SIZE):
        while 1:
            try:
                data+=self.request.recv(BUFFER_SIZE, socket.MSG_DONTWAIT)
            except:
                #error means no more data
                break
    if (data != ""): 
        #processing input
        dbg="Incomming message",data.encode("hex")
        logging.info(dbg)
        ret=process_request(data.encode("hex")) 
        if ret==ERROR:
            dbg="Error responding",ret
            logging.error(dbg)
        else:
            if ret==SKIP:
                dbg="Skipping response",ret
                logging.info(dbg)                
            else:
                dbg="Sending response",ret
                logging.info(dbg)
                conn.send(ret.decode("hex"))    
    else:
        #no data found exit loop (posible closed socket)        
        # remove it from sock_list
        sock_list.remove(conn)
        conn.close()

def handle_CMD(srv):
    conn,address=srv.accept()
    #get input ,wait if no data
    data=conn.recv(BUFFER_SIZE)
    #suspect more data (try to get it all without stopping if no data)
    if (len(data)==BUFFER_SIZE):
        while 1:
            try:
                data+=self.request.recv(BUFFER_SIZE, socket.MSG_DONTWAIT)
            except:
                #error means no more data
                break
    if (data != ""): 
        #processing input
        dbg="Incomming CMD",data.encode("hex")
        logging.info(dbg)
        ret=process_CMD(data.encode("hex")) 
        if ret==ERROR:
            dbg="Quitting",ret
            logging.error(dbg)
            conn.close()
            return ERROR
        else:
            dbg="Sending command",ret
            logging.info(dbg)
            sock_list[-1].send(ret.decode("hex"))  
    conn.close()
    return
 
 
# Create CEA response to CER request
        
def create_CEA(H):
    global DEST_REALM
    CER_avps=splitMsgAVPs(H.msg)
    DEST_REALM=findAVP("Origin-Realm",CER_avps)   
         
    # Let's build Capabilites-Exchange Answer
    CEA_avps=[]
    CEA_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    CEA_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    CEA_avps.append(encodeAVP("Vendor-Id", 11111))
    CEA_avps.append(encodeAVP("Product-Name", "PCRF-SIM"))
    #CEA_avps.append(encodeAVP("Host-IP-Address", "127.0.0.1"))
    CEA_avps.append(encodeAVP('Auth-Application-Id', 16777238))
    CEA_avps.append(encodeAVP("Supported-Vendor-Id", 10415))
    CEA_avps.append(encodeAVP("Supported-Vendor-Id", 11112))
    CEA_avps.append(encodeAVP("Supported-Vendor-Id", 0))
    CEA_avps.append(encodeAVP("Result-Code", 2001))   #DIAMETER_SUCCESS 2001
    # Create message header (empty)
    CEA=HDRItem()
    # Set command code
    CEA.cmd=H.cmd
    # Set Application-id
    CEA.appId=H.appId
    # Set Hop-by-Hop and End-to-End from request
    CEA.HopByHop=H.HopByHop
    CEA.EndToEnd=H.EndToEnd
    # Add AVPs to header and calculate remaining fields
    ret=createRes(CEA,CEA_avps)
    # ret now contains CEA Response as hex string
    return ret


# Create AAA response to AAR request (Rx)
        
def create_AAA(H):
    global DEST_REALM
    AAR_avps=splitMsgAVPs(H.msg)
    DEST_REALM=findAVP("Origin-Realm",AAR_avps)   
         
    # Let's build AA Answer
    AAA_avps=[]
    AAA_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    AAA_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    AAA_avps.append(encodeAVP("Vendor-Id", 11111))
    AAA_avps.append(encodeAVP("Product-Name", "PCRF-SIM"))
    AAA_avps.append(encodeAVP('Auth-Application-Id', 16777236))
    AAA_avps.append(encodeAVP("Supported-Vendor-Id", 10415))
    AAA_avps.append(encodeAVP("Supported-Vendor-Id", 11112))
    AAA_avps.append(encodeAVP("Supported-Vendor-Id", 0))
    AAA_avps.append(encodeAVP("Result-Code", 2001))   #DIAMETER_SUCCESS 2001
    # Create message header (empty)
    AAA=HDRItem()
    # Set command code
    AAA.cmd=H.cmd
    # Set Application-id
    AAA.appId=H.appId
    # Set Hop-by-Hop and End-to-End from request
    AAA.HopByHop=H.HopByHop
    AAA.EndToEnd=H.EndToEnd
    # Add AVPs to header and calculate remaining fields
    ret=createRes(AAA,AAA_avps)
    # ret now contains AAA Response as hex string
    return ret


# Create Watchdog response in reply to Watchdog request . We reply with 2001 OK

def create_DWA(H):
    # Let's build Diameter-WatchdogAnswer 
    DWA_avps=[]
    DWA_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    DWA_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    DWA_avps.append(encodeAVP("Result-Code", 2001)) #DIAMETER_SUCCESS 2001
    # Create message header (empty)
    DWA=HDRItem()
    # Set command code
    DWA.cmd=H.cmd
    # Set Application-id
    DWA.appId=H.appId
    # Set Hop-by-Hop and End-to-End from request
    DWA.HopByHop=H.HopByHop
    DWA.EndToEnd=H.EndToEnd
    # Add AVPs to header and calculate remaining fields
    ret=createRes(DWA,DWA_avps)
    # ret now contains DWA Response as hex string
    return ret

# Create Disconnect_Peer response in reply to Disconnect_Peer request. We just reply with 2001 OK for testing purposes


def create_DPA(H):
    # Let's build Diameter-Disconnect Peer Answer
    DPA_avps=[]
    DPA_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    DPA_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    DPA_avps.append(encodeAVP("Result-Code", 2001)) #DIAMETER_SUCCESS 2001
    # Create message header (empty)
    DPA=HDRItem()
    # Set command code
    DPA.cmd=H.cmd
    # Set Application-id
    DPA.appId=H.appId
    # Set Hop-by-Hop and End-to-End from request
    DPA.HopByHop=H.HopByHop
    DPA.EndToEnd=H.EndToEnd
    # Add AVPs to header and calculate remaining fields
    ret=createRes(DPA,DPA_avps)
    # ret now contains DPA Response as hex string
    return ret

# Create Unable To Comply response in reply to request which is not understood. We reply with 5012 result-code AVP


def create_UTC(H,msg):
    # Let's build Unable to comply packet
    DWA_avps=[]
    DWA_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    DWA_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    DWA_avps.append(encodeAVP("Result-Code", 5012)) #UNABLE TO COMPLY 5012
    DWA_avps.append(encodeAVP("Error-Message", msg))
    # Create message header (empty)
    DWA=HDRItem()
    # Set command code
    DWA.cmd=H.cmd
    # Set Application-id
    DWA.appId=H.appId
    # Set Hop-by-Hop and End-to-End from request
    DWA.HopByHop=H.HopByHop
    DWA.EndToEnd=H.EndToEnd
    # Add AVPs to header and calculate remaining fields
    ret=createRes(DWA,DWA_avps)
    # ret now contains DWA Response as hex string
    return ret


# And here we create CCA-I(U) responses in reply to CCR -I(U) requests. 

# 1. We parse CCR-I(U) and search for sessionid and msisdn. 
# 3. We send back CCA-I(U) with one PCC Rule


def create_CCA(H):
            
            
     # Let's parse the CCR and get Session-Id and MSISDN of the user, it is assumed that user is already authenticated in PCEF - (has its IP number):
     
     CCR_avps=splitMsgAVPs(H.msg)
     try:
      CCA_SESSION=findAVP("Session-Id",CCR_avps)
     except:
      pass
     try:
      CCA_SSID=findAVP("Subscription-Id",CCR_avps) 
     except:
      pass
     try:
      CCA_MSISDN=findAVP("Subscription-Id-Data",CCA_SSID)
     except:
      pass
     try:
      CCA_IPADDRESS=findAVP("Framed-IP-Address",CCR_avps)
     except:
      pass
     try:
      CCA_REQUEST_TYPE=findAVP("CC-Request-Type",CCR_avps)
     except:
      pass

     
     if CCA_REQUEST_TYPE in [1]:
          
     # This is CCR-I request from PCEF with Subscription-Id-Data (MSISDN) 

       # Let's build CCA-I 2001 Success with msisdn and Charging-Rule-Install values
       CCA_avps=[ ]
       CCA_avps.append(encodeAVP('Result-Code', '2001'))
       CCA_avps.append(encodeAVP('Session-Id', CCA_SESSION))
       CCA_avps.append(encodeAVP('Origin-Host', ORIGIN_HOST))
       CCA_avps.append(encodeAVP('Origin-Realm', ORIGIN_REALM))
       CCA_avps.append(encodeAVP('CC-Request-Type', CCA_REQUEST_TYPE))
       CCA_avps.append(encodeAVP('CC-Request-Number', 0))
       CCA_avps.append(encodeAVP('Auth-Application-Id', 16777238))
       CCA_avps.append(encodeAVP('Supported-Vendor-Id', 0))
       CCA_avps.append(encodeAVP('Supported-Vendor-Id', 10415))
       CCA_avps.append(encodeAVP('Supported-Vendor-Id', 11112))
       CCA_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', CCA_MSISDN), encodeAVP('Subscription-Id-Type', 0)]))
       CCA_avps.append(encodeAVP('Charging-Rule-Install',[encodeAVP('Charging-Rule-Name','activate_smtp_service'),encodeAVP('Charging-Rule-Name', 'set_service_id_1234_on')]))
       # Create message header (empty)
       CCA=HDRItem()
       # Set command code
       CCA.cmd=H.cmd
       # Set Application-id
       CCA.appId=H.appId
       # Set Hop-by-Hop and End-to-End from request
       CCA.HopByHop=H.HopByHop
       CCA.EndToEnd=H.EndToEnd
       # Add AVPs to header and calculate remaining fields
       ret=createRes(CCA,CCA_avps)
       # ret now contains CCA Response as hex string  
            
       return ret
       
     elif CCA_REQUEST_TYPE in [2]:
     
     
     # This is CCR-U request with msisdn . We will return Result code 2001 Success
     
       # Let's build CCA-I 2001 Success with msisdn and Charging-Rule-Install
       CCA_avps=[ ]
       CCA_avps.append(encodeAVP('Result-Code', '2001'))
       CCA_avps.append(encodeAVP('Session-Id', CCA_SESSION))
       CCA_avps.append(encodeAVP('Origin-Host', ORIGIN_HOST))
       CCA_avps.append(encodeAVP('Origin-Realm', ORIGIN_REALM))
       CCA_avps.append(encodeAVP('CC-Request-Type', CCA_REQUEST_TYPE))
       CCA_avps.append(encodeAVP('CC-Request-Number', 0))
       CCA_avps.append(encodeAVP('Auth-Application-Id', 16777238))
       CCA_avps.append(encodeAVP('Supported-Vendor-Id', 0))
       CCA_avps.append(encodeAVP('Supported-Vendor-Id', 10415))
       CCA_avps.append(encodeAVP('Supported-Vendor-Id', 11112))
       CCA_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', CCA_MSISDN), encodeAVP('Subscription-Id-Type', 0)]))
       CCA_avps.append(encodeAVP('Charging-Rule-Install',[encodeAVP('Charging-Rule-Name','activate_smtp_service')]))
       CCA_avps.append(encodeAVP('Charging-Rule-Install',[encodeAVP('Charging-Rule-Name','set_service_1234_on')]))
       # Create message header (empty)
       CCA=HDRItem()
       # Set command code
       CCA.cmd=H.cmd
       # Set Application-id
       CCA.appId=H.appId
       # Set Hop-by-Hop and End-to-End from request
       CCA.HopByHop=H.HopByHop
       CCA.EndToEnd=H.EndToEnd
       # Add AVPs to header and calculate remaining fields
       ret=createRes(CCA,CCA_avps)
       # ret now contains CCA Response as hex string  
            
       return ret     
      
     elif CCA_REQUEST_TYPE in [3]:
	                 
       # Here we will send 2001 Success Termination response to CCR-T --> CCA-T
       
       CCA_avps=[ ]
       CCA_avps.append(encodeAVP('Result-Code', '2001'))
       CCA_avps.append(encodeAVP('Session-Id', CCA_SESSION))
       CCA_avps.append(encodeAVP('Origin-Host', ORIGIN_HOST))
       CCA_avps.append(encodeAVP('Origin-Realm',ORIGIN_REALM))
       CCA_avps.append(encodeAVP('CC-Request-Type', CCA_REQUEST_TYPE))
       CCA_avps.append(encodeAVP('CC-Request-Number', 0))
       CCA_avps.append(encodeAVP('Auth-Application-Id', 16777238))
       CCA_avps.append(encodeAVP('Supported-Vendor-Id', 0))
       CCA_avps.append(encodeAVP('Supported-Vendor-Id', 10415))
       CCA_avps.append(encodeAVP('Supported-Vendor-Id', 11112))
	#CCA_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', CCA_MSISDN), encodeAVP('Subscription-Id-Type', 0)]))
	# Create message header (empty)
       CCA=HDRItem()
	# Set command code
       CCA.cmd=H.cmd
	# Set Application-id
       CCA.appId=H.appId
	# Set Hop-by-Hop and End-to-End from request
       CCA.HopByHop=H.HopByHop
       CCA.EndToEnd=H.EndToEnd
	# Add AVPs to header and calculate remaining fields
       ret=createRes(CCA,CCA_avps)
	# ret now contains CCA Response as hex string  
       return ret
                       
def appendToCMD(H):
    # We need to append Host&Realm to message
    CMD_avps=splitMsgAVPs(H.msg)
    CMD_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    CMD_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    CMD_avps.append(encodeAVP("Destination-Realm", DEST_REALM))
    ret=createRes(H,CMD_avps)
    dbg="Appended ",ret
    logging.info(dbg)
    return ret

def process_CMD(rawdata):
    dbg="Processing CMD",rawdata
    logging.info(dbg)
    if rawdata[:2]=="01":
        #Diammeter command
        logging.info("Processing diameter request")
        H=HDRItem()
        stripHdr(H,rawdata)
        return appendToCMD(H)
    else:
        return ERROR

def process_request(rawdata):
    H=HDRItem()
    stripHdr(H,rawdata)
    dbg="Processing",dictCOMMANDcode2name(H.flags,H.cmd)
    logging.info(dbg)
    if H.flags & DIAMETER_HDR_REQUEST==0:
        # If Answer no need to do anything
        # Messages PCRF->PCEF are sent with external test_*.py script
        return SKIP
    if H.cmd==257:  # Capabilities-Exchange
        return create_CEA(H)
    if H.cmd==280:  # Device-Watchdog
        return create_DWA(H)
    if H.cmd==272:  # Credit-Control
        return create_CCA(H)        
    if H.cmd==282:  # Disconnect-Request-Peer
        return create_DPA(H)
    if H.cmd==265:  # AAR/AAA
        return create_AAA(H)        
    return create_UTC(H,"Unknown command code")

    
def Quit():
    for conn in sock_list:
        conn.close()
    sys.exit(0)
    
if __name__ == "__main__":
    # level for decoding are: DEBUG, INFO, WARNING, ERROR, CRITICAL
    #logging.basicConfig(level=logging.INFO)

    # Define server_host:port to use (empty string means localhost)
    
    # MANDATORY TO CHANGE: THIS IS IP/PORT OF PCRF SERVER
    
    HOST = "127.0.0.1"
    DIAM_PORT = 3868

    # Define command port to trigger RAR-T/RAR-U and other PCRF initiated (Push) commands
    CMD_PORT = 3869
    
    # MANDATORY TO CHANGE: TO YOUR PCRF REALM values
    
    ORIGIN_HOST = "pcrf.myrealm.example"
    ORIGIN_REALM = "myrealm.example"
    DEST_REALM = ""
    
    LoadDictionary("../dictDiameter.xml")

    BUFFER_SIZE=1024    
    MAX_CLIENTS=5
    sock_list=[]
   
    # Create the server, binding to HOST:DIAM_PORT
    PCRF_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # fix "Address already in use" error upon restart
    PCRF_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    PCRF_server.bind((HOST, DIAM_PORT))  
    PCRF_server.listen(MAX_CLIENTS)
    sock_list.append(PCRF_server)

    # Create the server, binding to HOST:CMD_PORT
    CMD_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # fix "Address already in use" error upon restart
    CMD_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    CMD_server.bind((HOST, CMD_PORT))  
    CMD_server.listen(MAX_CLIENTS)
    sock_list.append(CMD_server)
    logging.info("Server started")
    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    while True:
        try:
            read, write, error = select.select(sock_list,[],[],1)
        except:
            break
        for r in read:
            logging.info("Incoming data")
            # First handle command connection to CMD_server
            if r==CMD_server:
                if handle_CMD(CMD_server)==ERROR:
                    logging.info("Exiting")
                    Quit()
            else:
                # Is it new or existing connection
                if r==PCRF_server:
                    # New connections: accept on new socket
                    conn,addr=PCRF_server.accept()
                    sock_list.append(conn)
                    if handle_PCRF(conn)==ERROR:
                        Quit()
                else:
                    if handle_PCRF(r)==ERROR:
                        Quit()
    Quit()

######################################################        
