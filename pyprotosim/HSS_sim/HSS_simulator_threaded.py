#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - November 2012
# Version 0.3.1, Last change on Nov 10, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# HSS Simulator (multiple clients) build upon libDiameter 
# interrupt the program with Ctrl-C

#Next two lines include parent directory where libDiameter is located
import sys
sys.path.append("..")
# Remove them if everything is in the same dir

import socket
import thread
import select
import logging
import Queue
from libDiameter import *

SKIP=0

def handle_msg(conn,data):
    dbg="handle_msg:Handling",len(data)
    logging.info(dbg)
    ret=process_request(data.encode("hex"))
    logging.info("handle_msg:REQ processed")
    if ret==ERROR:
        dbg="Error responding",ret
        logging.error(dbg)
    else:
        if ret==SKIP:
            dbg="Skipping response",ret
            logging.info(dbg)                
        else:
            dbg="handle_msg:Sending response",ret
            logging.info(dbg)
            conn.send(ret.decode("hex")) 
                        
def handle_HSS(aaa,addr):
    # conn is the TCP socket connected to the client
    while True:
        try:
            read, write, error = select.select([aaa],[],[],SOCK_TIMEOUT)
        except:
            logging.info("After select except")
            break
        for r in read:
            #get input ,wait if no data
            logging.info("handle_HSS:We have incoming data")
            data=r.recv(BUFFER_SIZE)
            #suspect more data (try to get it all without stopping if no data)
            if (len(data)==BUFFER_SIZE):
                while 1:
                    try:
                        data+=r.recv(BUFFER_SIZE, socket.MSG_DONTWAIT)
                    except:
                        #error means no more data
                        break
            if (data != ""): 
                #processing input
                dbg="handle_HSS:Incomming message from ",conn.getpeername(),"size",len(data)
                logging.info(dbg)
                handle_msg(r,data)
                logging.info("handle_HSS:handle_msg done")
            else:
                # Connection closed?
                return
        if not CMDOut.empty():
            print "handle_HSS:Processing CMD"
            cmd=CMDOut.get()
            dbg="handle_HSS:Read from Qo",cmd
            logging.info(dbg)
            ret=process_CMD(cmd)
            dbg="handle_HSS:Processed ",ret
            logging.info(dbg)
            if ret!=ERROR:
                aaa.send(ret.decode("hex"))

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
        dbg="handle_CMD:Incomming CMD",data.encode("hex")
        logging.info(dbg)
        CMDOut.put(data.encode("hex"))
        dbg="handle_CMD:Put in Qo",data.encode("hex")
        logging.info(dbg)
        try:
            data=CMDIn.get(True,4)
            dbg="handle_CMD:Read from Qi",data
            logging.info(dbg)
        except:
            data=""
        ret=process_CMD(data) 
        if ret!=ERROR:
            dbg="handle_CMD:Sending command",ret
            logging.info(dbg)
            conn.send(ret.decode("hex"))    
    conn.close()
    return 
    
def create_CEA(H):
    global DEST_REALM
    CER_avps=splitMsgAVPs(H.msg)
    DEST_REALM=findAVP("Origin-Realm",CER_avps)     
    # Let's build Capabilites-Exchange Answer
    CEA_avps=[]
    CEA_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    CEA_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    CEA_avps.append(encodeAVP("Vendor-Id", 28458))
    CEA_avps.append(encodeAVP("Product-Name", "aaaClient-HSSsim"))
    CEA_avps.append(encodeAVP("Host-IP-Address", "1.1.3.5"))
    CEA_avps.append(encodeAVP("Acct-Application-Id", 4294967295L))
    CEA_avps.append(encodeAVP("Supported-Vendor-Id", 10415))
    CEA_avps.append(encodeAVP("Supported-Vendor-Id", 12951))
    CEA_avps.append(encodeAVP("Supported-Vendor-Id", 5535))
    CEA_avps.append(encodeAVP("Inband-Security-Id", 0))
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

def create_SAA(H):
    # Let's build Service-Asignment Answer
    # We need Session-Id from Request
    SAR_avps=splitMsgAVPs(H.msg)
    sesID=findAVP("Session-Id",SAR_avps) 
    saType=findAVP("Server-Assignment-Type",SAR_avps)
    userName=findAVP("User-Name",SAR_avps)
    SAA_avps=[]
    SAA_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    SAA_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    SAA_avps.append(encodeAVP("Session-Id", sesID))
    SAA_avps.append(encodeAVP("User-Name", userName))
    # Grouped AVPs are encoded like this
    SAA_avps.append(encodeAVP("Vendor-Specific-Application-Id",[
        encodeAVP("Vendor-Id",dictVENDORid2code('TGPP')),
        encodeAVP("Auth-Application-Id",H.appId)]))
    SAA_avps.append(encodeAVP("Auth-Session-State", 1)) # 1 - NO_STATE_MAINTAINED    
    SAA_avps.append(encodeAVP("Result-Code", 2001))     # 2001 - DIAMETER_SUCCESS
    if saType==1:   #REGISTRATION
        #Non-3GPP-User-Data
        SAA_avps.append(encodeAVP('Non-3GPP-User-Data', [
            encodeAVP('Subscription-Id', [
                encodeAVP('Subscription-Id-Data', '121112222000623'),
                encodeAVP('Subscription-Id-Type', 0)]), 
            encodeAVP('Non-3GPP-IP-Access', 0),
            encodeAVP('Non-3GPP-IP-Access-APN', 0),
            encodeAVP('MIP6-Feature-Vector', 1),
            encodeAVP('APN-Configuration', [
                encodeAVP('Context-Identifier', 1), 
                encodeAVP('Service-Selection', 'a1'), 
                encodeAVP('PDN-Type', 0), 
                encodeAVP('AMBR', [
                    encodeAVP('Max-Requested-Bandwidth-UL', 500), 
                    encodeAVP('Max-Requested-Bandwidth-DL', 500)
                ]), 
                encodeAVP('EPS-Subscribed-QoS-Profile', [
                    encodeAVP('QoS-Class-Identifier', 1), 
                    encodeAVP('Allocation-Retention-Priority', [
                        encodeAVP('Priority-Level', 0)
                    ])
                ])
            ]),
            encodeAVP('Context-Identifier', 0)
        ]))
    # Create message header (empty)
    SAA=HDRItem()
    # Set command code
    SAA.cmd=H.cmd
    # Set Application-id
    SAA.appId=H.appId
    # Set Hop-by-Hop and End-to-End from request
    SAA.HopByHop=H.HopByHop
    SAA.EndToEnd=H.EndToEnd
    # Add AVPs to header and calculate remaining fields
    ret=createRes(SAA,SAA_avps)
    # ret now contains SAA Response as hex string
    return ret    
    
def build_MAA(H,AppId,UserName,SIP_Auth):
    # Let's build Multimedia-Authentication Answer
    MAA_avps=[]
    MAA_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    MAA_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    MAA_avps.append(encodeAVP("Vendor-Specific-Application-Id",[
        encodeAVP("Vendor-Id",dictVENDORid2code('TGPP')),
        encodeAVP("Auth-Application-Id",AppId)])) 
    MAA_avps.append(encodeAVP("Auth-Session-State",1)) #NO_STATE_MAINTAINED
    MAA_avps.append(encodeAVP("User-Name",UserName))
    MAA_avps.append(encodeAVP("Result-Code", 2001)) #DIAMETER_SUCCESS 2001
    MAA_avps.append(encodeAVP("SIP-Number-Auth-Items",len(SIP_Auth)))
    for s in SIP_Auth:
            MAA_avps.append(s)
    # Create message header (empty)
    MAA=HDRItem()
    # Set command code
    MAA.cmd=H.cmd
    # Set Application-id
    MAA.appId=H.appId
    # Set Hop-by-Hop and End-to-End from request
    MAA.HopByHop=H.HopByHop
    MAA.EndToEnd=H.EndToEnd
    # Add AVPs to header and calculate remaining fields
    ret=createRes(MAA,MAA_avps)
    # ret now contains MAA Response as hex string
    return ret

def create_MAA(H):
    # We need to decode SIP-Auth-Data-Item
    # If it has Authentication-Method : for radius 0=SIM, 1=AKA
    # If it has SIP-Authentication-Scheme, :for diameter value states AKA or AKA'
    MAR_avps=splitMsgAVPs(H.msg)
    UserName=findAVP("User-Name",MAR_avps)
    NumOfItems=findAVP("SIP-Number-Auth-Items",MAR_avps)
    Auth_Data=findAVP("SIP-Auth-Data-Item",MAR_avps)
    Auth_Method=findAVP("Authentication-Method",Auth_Data)
    Auth_Scheme=findAVP("SIP-Authentication-Scheme",Auth_Data)
    if Auth_Method==0:
        logging.info("Responding with Wx SIM")
        return build_MAA(H,16777219,UserName,getRadiusTriplet(UserName,NumOfItems,Auth_Method))
    if Auth_Method==1:
        logging.info("Responding with Wx AKA")
        return build_MAA(H,16777219,UserName,getRadiusQuintet(UserName,NumOfItems,Auth_Method))
    if Auth_Scheme=="EAP-AKA":
        logging.info("Responding with SWx AKA")
        return build_MAA(H,16777265,UserName,getQuintet(UserName,NumOfItems,Auth_Scheme))
    if Auth_Scheme=="EAP-AKA'":
        logging.info("Responding with SWx AKA'")
        return build_MAA(H,16777265,UserName,getQuintet(UserName,NumOfItems,Auth_Scheme))
    return ERROR
    
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
    dbg="process_CMD:Processing CMD",rawdata
    logging.info(dbg)
    if rawdata[:2]=="01":
        #Diammeter command
        logging.info("process_CMD:Processing diameter request")
        H=HDRItem()
        stripHdr(H,rawdata)
        return appendToCMD(H)
    else:
        return ERROR

def process_request(rawdata):
    H=HDRItem()
    stripHdr(H,rawdata)
    dbg="process_request:Processing",dictCOMMANDcode2name(H.flags,H.cmd)
    logging.info(dbg)
    if H.flags & DIAMETER_HDR_REQUEST==0:
        # If Answer no need to do anything
        # Messages HSS->AAA are send with external put_*.py script
        CMDIn.put(rawdata)
        return SKIP
    if H.cmd==257:  # Capabilities-Exchange
        return create_CEA(H)
    if H.cmd==280:  # Device-Watchdog
        return create_DWA(H)
    if H.cmd==301:  # Server-Assignment
        return create_SAA(H)        
    if H.cmd==303:  # Multimedia-Auth
        return create_MAA(H)
    return create_UTC(H,"Unknown command code")

def getRadiusTriplet(UserName,NumOfItems,AuthMethod):
    ret=[]
    for i in range(NumOfItems):
        ret.append(encodeAVP("SIP-Auth-Data-Item",[
            encodeAVP("SIP-Item-Number",i+1),
            encodeAVP("Authentication-Method",AuthMethod),
            encodeAVP("Authentication-Information-SIM","8b7e0f1147f9af050809bbaf50881dbb08014ca81b36d9fa".decode("hex")),
            encodeAVP("Authorization-Information-SIM","334131fc".decode("hex")) ]))
    return ret

def getRadiusQuintet(UserName,NumOfItems,AuthMethod):
    ret=[]
    for i in range(NumOfItems):
        ret.append(encodeAVP("SIP-Auth-Data-Item",[
            encodeAVP("Authentication-Method",AuthMethod),
            encodeAVP("SIP-Authorization","e818fbf691ae3b97".decode("hex")),
            encodeAVP("Confidentiality-Key","f16a4bb5112dba580132e29882fec143".decode("hex")),
            encodeAVP("Integrity-Key","952a44900b7faff249763475b3aa77ee".decode("hex")),
            encodeAVP("SIP-Authenticate","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb52bdc449bce0800098c737a73bc7c191".decode("hex"))
             ]))
    return ret

def getQuintet(UserName,NumOfItems,AuthScheme):
    ret=[]
    for i in range(NumOfItems):
        ret.append(encodeAVP("SIP-Auth-Data-Item",[
            encodeAVP("SIP-Authentication-Scheme",AuthScheme),
            encodeAVP("SIP-Authorization","e818fbf691ae3b97".decode("hex")),
            encodeAVP("Confidentiality-Key","f16a4bb5112dba580132e29882fec143".decode("hex")),
            encodeAVP("Integrity-Key","952a44900b7faff249763475b3aa77ee".decode("hex")),
            encodeAVP("SIP-Authenticate","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb52bdc449bce0800098c737a73bc7c191".decode("hex"))
             ]))
    return ret

def Quit():
    HSS_server.close()
    CMD_server.close()
    sys.exit()
    
if __name__ == "__main__":
    # level for decoding are: DEBUG, INFO, WARNING, ERROR, CRITICAL
    #logging.basicConfig(filename='log', level=logging.INFO)
    logging.basicConfig(level=logging.INFO)

    # Define server_host:port to use (empty string means localhost)
    HOST = ""
    DIAM_PORT = 3868

    # Define command port to trigger PPR/RTR and other commands
    CMD_PORT = 3869
    
    ORIGIN_HOST = "server.test.com"
    ORIGIN_REALM = "test.com"
    DEST_REALM = ""
    
    LoadDictionary("../dictDiameter.xml")

    BUFFER_SIZE=1024    
    MAX_CLIENTS=3
    SOCK_TIMEOUT=0.5
   
    CMDIn=Queue.Queue()
    CMDOut=Queue.Queue()
    # Create the server, binding to HOST:DIAM_PORT
    HSS_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # fix "Address already in use" error upon restart
    HSS_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    HSS_server.bind((HOST, DIAM_PORT))  
    HSS_server.listen(MAX_CLIENTS)

    # Create the server, binding to HOST:CMD_PORT
    CMD_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # fix "Address already in use" error upon restart
    CMD_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    CMD_server.bind((HOST, CMD_PORT))  
    CMD_server.listen(MAX_CLIENTS)
    logging.info("Server started")
    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    while True:
        try:
            read, write, error = select.select([HSS_server,CMD_server],[],[])
        except:
            break
        for r in read:
            logging.info("Incoming data")
            # First handle command connection to CMD_server
            if r==CMD_server:
                handle_CMD(CMD_server)
            else:
                # New connections: accept on new socket
                conn,addr=HSS_server.accept()
                thread.start_new_thread(handle_HSS,(conn,addr))
    Quit()

######################################################        
# History
# 0.2.7 - Sep 28, 2012 - initial version
# 0.2.8 - Oct 04, 2012 - tested radius SIM/AKA OK
# 0.2.9 - Oct 10, 2012 - added SAR/SAA
# 0.3.1 - Nov 09, 2012 - multiple connections allowed
#                      - added PPR, RTR (via ext command)
#                      - SAA fixed

