#!/usr/bin/python
####################################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# PCRF simulator with SPR support as example added by L.Belov <lavrbel@gmail.com>
# February 2012 - March 2014
# Version 0.1.1, Last change on Mar 11, 2014
# This software is distributed under the terms of BSD license.    
#####################################################################################
#####################################################################################
# Simple PCRF GX SIMULATOR server example with SPR support and static PCC rules.
# PCRF simulator will use its internal SPR DB to reply on CCR-I, CCR-U, 
#  CCR-T requests with CCA-I(U) and one PCC Charging-Install Rule.
# Mofify your own PCC rules in SPR DB below  
# Set your IP address in HOST parameter : e.g HOST = "127.0.0.1"
# This server supports CER,DWR,DPR,CCR-I,CCR-U,CCR-T,RAR-U,RAR-T
# History of changes:
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

######## SPR MODIFICATIONS CAN BE DONE HERE ##########################################

# SPR USER DATABASE

spr_db = {'1234567890':{'msisdn':'1234567890', 'sessionid':'value_1', 'imsi':'123456789012345','pcc_profile':'basic'},
          '1234567891':{'msisdn':'1234567891', 'sessionid':'value_2', 'imsi':'123456789012346','pcc_profile':'highspeed'},
          '1234567892':{'msisdn':'1234567892', 'sessionid':'value_3', 'imsi':'123456789012347','pcc_profile':'superfast'}}

# PCC STATIC PROFILES

pcc_db = {'basic':{'pcc_rule':'activate_qos_basic'},
          'highspeed':{'pcc_rule':'activate_qos_highspeed'},
          'superfast':{'pcc_rule':'activate_qos_superfast'}}

# PCC PROFILES DEFINITIONS

basic = {'qos_info':{'max_bitrate_ul':'500000000','max_bitrate_dl':'1000000000'}, 'eps_qos_default':'QCI_9','prioroty_level':'10'}
highspeed = {'qos_info':{'max_bitrate_ul':'1000000000','max_bitrate_dl':'2000000000'}, 'eps_qos_default':'QCI_5','prioroty_level':'5'}
superfast = {'qos_info':{'max_bitrate_ul':'2000000000','max_bitrate_dl':'5000000000'}, 'eps_qos_default':'QCI_1','prioroty_level':'1'}


######################## END OF SPR MODIFICATIONS ###################################

######################## START OF SPR FUNCTIONS   ###################################

# Function to check if user is valid in SPR database

def check_valid_user(identity):
  id = identity
  if id in spr_db:
   return True
  else:
   return False
	
# Function to extract PCC profile from user

def check_profile_values(identity):
  id = identity
  if id in spr_db:
   sessionid = spr_db[id]['sessionid']
   msisdn = spr_db[id]['msisdn']
   imsi = spr_db[id]['imsi']
   pcc_profile = spr_db[id]['pcc_profile']  
   return sessionid,imsi,msisdn,pcc_profile
  else:
   return False

# Function to set PCC profile values

def set_pcc_profile(pcc_profile):
  profile = pcc_profile
  if profile == 'basic':
    max_bitrate_ul = basic['qos_info']['max_bitrate_ul']
    max_bitrate_dl = basic['qos_info']['max_bitrate_dl']
    eps_qos_default = basic['eps_qos_default']
    prioroty_level = basic['prioroty_level']
  elif profile == 'highspeed':
    max_bitrate_ul = highspeed['qos_info']['max_bitrate_ul']
    max_bitrate_dl = highspeed['qos_info']['max_bitrate_dl']
    eps_qos_default = highspeed['eps_qos_default']
    prioroty_level = highspeed['prioroty_level']
  elif profile == 'superfast':
    max_bitrate_ul = superfast['qos_info']['max_bitrate_ul']
    max_bitrate_dl = superfast['qos_info']['max_bitrate_dl']
    eps_qos_default = superfast['eps_qos_default']
    prioroty_level = superfast['prioroty_level']
    
  return max_bitrate_ul,max_bitrate_dl,eps_qos_default,prioroty_level


def update_sessionid(identity,sessionid):
   id = identity
   sessionid = sessionid
   if id in spr_db:
     # Update sessionid for RAR requests in SPR DB
     sessionid_updated = spr_db[id]['sessionid']= sessionid
     print spr_db[id]['sessionid']
   else:
     return False

####################END OF SPR FUNCTIONS #############################################



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
    CEA_avps.append(encodeAVP('Auth-Application-Id', 16777238))
    CEA_avps.append(encodeAVP("Supported-Vendor-Id", 10415))
    CEA_avps.append(encodeAVP("Supported-Vendor-Id", 11111))
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

# 1. We parse CCR-I(U) and search for sessionid and msisdn . Then we make SPR query with user's identity == msisdn. 
#    We get answer from SPR DB and parse SPR response and check pcc_rule profile value. 
# 2. If, for example, pcc_rule profile value is set to 'basic', then we send CCA with PCC Charging-Rule-Install AVPs taken from pcc-rule profiles table
# 3. If user identity is not found in SPR , we send DIAMETER result-code 5003 NOT AUTHORIZED

def create_CCA(H):
            
            
     # Let's parse the CCR and get Session-Id and MSISDN of the user, it is assumed that user is already authenticated in PCEF - has its IP address:
     
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
     
     
     # This is CCR-I request from PCEF with Subscription-Id-Data (MSISDN) used as a filter for SPR. SPR will return  subscriber's data with PCC rule profile data

      SPR_FILTER=CCA_MSISDN
      identity = str(SPR_FILTER)
      sessionid_spr = str(CCA_SESSION)
      valid_user = check_valid_user(identity)
      if valid_user is True:
         sessionid, imsi,msisdn,pcc_profile = check_profile_values(identity)
         max_bitrate_ul,max_bitrate_dl,eps_qos_default,prioroty_level = set_pcc_profile(pcc_profile)
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
         CCA_avps.append(encodeAVP('Supported-Vendor-Id', 11111))
         CCA_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', msisdn), encodeAVP('Subscription-Id-Type', 0)]))
         CCA_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', imsi), encodeAVP('Subscription-Id-Type', 1)]))
         CCA_avps.append(encodeAVP('Charging-Rule-Install',[encodeAVP('Charging-Rule-Base-Name',pcc_profile)]))
         CCA_avps.append(encodeAVP('QoS-Information',[encodeAVP('APN-Aggregate-Max-Bitrate-UL',max_bitrate_ul),encodeAVP('APN-Aggregate-Max-Bitrate-DL',max_bitrate_dl)]))
         CCA_avps.append(encodeAVP('Online',0)) # not yet OCS supported
         CCA_avps.append(encodeAVP('Offline',0)) # not yet OFCS supported
         CCA_avps.append(encodeAVP('Default-EPS-Bearer-QoS',[encodeAVP('QoS-Class-Identifier',eps_qos_default)]))
         CCA_avps.append(encodeAVP('Allocation-Retention-Priority',[encodeAVP('Priority-Level',prioroty_level)]))
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
         
         # Update sessionid in SPR DB:
         
         update_sessionid(identity,sessionid_spr)
         
         return ret     
         
      elif valid_user is False:
         print "no, user doesn't exist. Sending DIAMETER 5003 answer"     
         # Let's build CCA-I 5003 Error
         CCA_avps=[ ]
         CCA_avps.append(encodeAVP('Result-Code', '5003'))
         CCA_avps.append(encodeAVP('Session-Id', CCA_SESSION))
         CCA_avps.append(encodeAVP('Origin-Host', ORIGIN_HOST))
         CCA_avps.append(encodeAVP('Origin-Realm', ORIGIN_REALM))
         CCA_avps.append(encodeAVP('CC-Request-Type', CCA_REQUEST_TYPE))
         CCA_avps.append(encodeAVP('CC-Request-Number', 0))
         CCA_avps.append(encodeAVP('Auth-Application-Id', 16777238))
         CCA_avps.append(encodeAVP('Supported-Vendor-Id', 0))
         CCA_avps.append(encodeAVP('Supported-Vendor-Id', 10415))
         CCA_avps.append(encodeAVP('Supported-Vendor-Id', 11111))
          
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
     # This is CCR-U request with msisdn which will be used as a filter to send to SPR. SPR will return updated other subscriber data with PCC rules
     
      SPR_FILTER=CCA_MSISDN
      identity = str(SPR_FILTER)
      sessionid_spr = str(CCA_SESSION)
      valid_user = check_valid_user(identity)
      if valid_user is True:
         sessionid, imsi,msisdn,pcc_profile = check_profile_values(identity)
         max_bitrate_ul,max_bitrate_dl,eps_qos_default,prioroty_level = set_pcc_profile(pcc_profile)
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
         CCA_avps.append(encodeAVP('Supported-Vendor-Id', 11111))
         CCA_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', msisdn), encodeAVP('Subscription-Id-Type', 0)]))
         CCA_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data', imsi), encodeAVP('Subscription-Id-Type', 1)]))
         CCA_avps.append(encodeAVP('Charging-Rule-Install',[encodeAVP('Charging-Rule-Base-Name',pcc_profile)]))
         CCA_avps.append(encodeAVP('QoS-Information',[encodeAVP('APN-Aggregate-Max-Bitrate-UL',max_bitrate_ul),encodeAVP('APN-Aggregate-Max-Bitrate-DL',max_bitrate_dl)]))
         CCA_avps.append(encodeAVP('Online',0))
         CCA_avps.append(encodeAVP('Offline',0))
         CCA_avps.append(encodeAVP('Default-EPS-Bearer-QoS',[encodeAVP('QoS-Class-Identifier',eps_qos_default)]))
         CCA_avps.append(encodeAVP('Allocation-Retention-Priority',[encodeAVP('Priority-Level',prioroty_level)]))
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
         
         # Update sessionid in SPR DB:
	          
         update_sessionid(identity,sessionid_spr)
            
         return ret     
         
      elif valid_user is False:
         print "no, user doesn't exist. Sending DIAMETER 5003 answer"     
         # Let's build CCA-I 5003 Error
         CCA_avps=[ ]
         CCA_avps.append(encodeAVP('Result-Code', '5003'))
         CCA_avps.append(encodeAVP('Session-Id', CCA_SESSION))
         CCA_avps.append(encodeAVP('Origin-Host', ORIGIN_HOST))
         CCA_avps.append(encodeAVP('Origin-Realm', ORIGIN_REALM))
         CCA_avps.append(encodeAVP('CC-Request-Type', CCA_REQUEST_TYPE))
         CCA_avps.append(encodeAVP('CC-Request-Number', 0))
         CCA_avps.append(encodeAVP('Auth-Application-Id', 16777238))
         CCA_avps.append(encodeAVP('Supported-Vendor-Id', 0))
         CCA_avps.append(encodeAVP('Supported-Vendor-Id', 10415))
         CCA_avps.append(encodeAVP('Supported-Vendor-Id', 11111))
          
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
       CCA_avps.append(encodeAVP('Supported-Vendor-Id', 11111))
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
                   
     else:
       # Let's build CCA-T with 5003
       CCA_avps=[ ]
       CCA_avps.append(encodeAVP('Result-Code', '5003'))
       CCA_avps.append(encodeAVP('Session-Id', CCA_SESSION))
       CCA_avps.append(encodeAVP('Origin-Host', ORIGIN_HOST))
       CCA_avps.append(encodeAVP('Origin-Realm', ORIGIN_REALM))
       CCA_avps.append(encodeAVP('CC-Request-Type', CCA_REQUEST_TYPE))
       CCA_avps.append(encodeAVP('CC-Request-Number', 0))
       CCA_avps.append(encodeAVP('Auth-Application-Id', 16777238))
       CCA_avps.append(encodeAVP('Supported-Vendor-Id', 0))
       CCA_avps.append(encodeAVP('Supported-Vendor-Id', 10415))
       CCA_avps.append(encodeAVP('Supported-Vendor-Id', 11111))
	 
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
