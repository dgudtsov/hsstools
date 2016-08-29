
# HSS Tools module

##################################################################
# Copyright (c) 2015-2016 Denis Gudtsov
# License - GPL
# https://github.com/dgudtsov/hsstools
#
# based on  Python Protocol Simulator project
# https://sourceforge.net/projects/pyprotosim/
##################################################################

from config_diam import *

import logging
hss_logger = logging.getLogger('hss_tools.aux')

import os
import sys
import socket
import datetime
import time

sys.path.append(pyprotosim_lib_path)
from libDiameter import *

DIAM_OK_CODE = [2001]

diam_error_codes = {
2002:"DIAMETER_LIMITED_SUCCESS",
3001:"DIAMETER_COMMAND_UNSUPPORTED",
3002:"DIAMETER_UNABLE_TO_DELIVER",
3003:"DIAMETER_REALM_NOT_SERVED",
3004:"DIAMETER_TOO_BUSY",
3005:"DIAMETER_LOOP_DETECTED",
3006:"DIAMETER_REDIRECT_INDICATION",
3007:"DIAMETER_APPLICATION_UNSUPPORTED",
3008:"DIAMETER_INVALID_HDR_BITS",
3009:"DIAMETER_INVALID_AVP_BITS",
3010:"DIAMETER_UNKNOWN_PEER",
4001:"DIAMETER_AUTHENTICATION_REJECTED",
4002:"DIAMETER_OUT_OF_SPACE",
4003:"ELECTION_LOST",
5001:"DIAMETER_AVP_UNSUPPORTED",
5002:"DIAMETER_UNKNOWN_SESSION_ID",
5003:"DIAMETER_AUTHORIZATION_REJECTED",
5004:"DIAMETER_INVALID_AVP_VALUE",
5005:"DIAMETER_MISSING_AVP",
5006:"DIAMETER_RESOURCES_EXCEEDED",
5007:"DIAMETER_CONTRADICTING_AVPS",
5008:"DIAMETER_AVP_NOT_ALLOWED",
5009:"DIAMETER_AVP_OCCURS_TOO_MANY_TIMES",
5010:"DIAMETER_NO_COMMON_APPLICATION",
5011:"DIAMETER_UNSUPPORTED_VERSION",
5012:"DIAMETER_UNABLE_TO_COMPLY",
5013:"DIAMETER_INVALID_BIT_IN_HEADER",
5014:"DIAMETER_INVALID_AVP_LENGTH",
5015:"DIAMETER_INVALID_MESSAGE_LENGTH",
5016:"DIAMETER_INVALID_AVP_BIT_COMBO",
5017:"DIAMETER_NO_COMMON_SECURITY"
}

diam_exp_error_codes = {
4100:"DIAMETER_USER_DATA_NOT_AVAILABLE",
4101:"DIAMETER_PRIOR_UPDATE_IN_PROGRESS",
4181:"DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE",
5001:"DIAMETER_ERROR_USER_UNKNOWN",
5002:"DIAMETER_ERROR_IDENTITIES_DONT_MATCH",
5003:"DIAMETER_ERROR_IDENTITY_NOT_REGISTERED",
5004:"DIAMETER_ERROR_ROAMING_NOT_ALLOWED",
5005:"DIAMETER_ERROR_IDENTITY_ALREADY_REGISTERED",
5006:"DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED",
5007:"DIAMETER_ERROR_IN_ASSIGNMENT_TYPE",
5008:"DIAMETER_ERROR_TOO_MUCH_DATA",
5009:"DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA",
5011:"DIAMETER_ERROR_FEATURE_UNSUPPORTED",
5100:"DIAMETER_ERROR_USER_DATA_NOT_RECOGNIZED",
5101:"DIAMETER_ERROR_OPERATION_NOT_ALLOWED",
5102:"DIAMETER_ERROR_USER_DATA_CANNOT_BE_READ",
5103:"DIAMETER_ERROR_USER_DATA_CANNOT_BE_MODIFIED",
5104:"DIAMETER_ERROR_USER_DATA_CANNOT_BE_NOTIFIED",
5105:"DIAMETER_ERROR_TRANSPARENT_DATA OUT_OF_SYNC",
5106:"DIAMETER_ERROR_SUBS_DATA_ABSENT",
5107:"DIAMETER_ERROR_NO_SUBSCRIPTION_TO_DATA",
5108:"DIAMETER_ERROR_DSAI_NOT_AVAILABLE",
5420:"DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION",
5421:"DIAMETER_ERROR_RAT_NOT_ALLOWED",
5422:"DIAMETER_ERROR_EQUIPMENT_UNKNOWN",
5423:"DIAMETER_ERROR_UNKOWN_SERVING_NODE",
5450:"DIAMETER_ERROR_USER_NO_NON_3GPP_SUBSCRIPTION",
5451:"DIAMETER_ERROR_USER_NO_APN_SUBSCRIPTION",
5452:"DIAMETER_ERROR_RAT_TYPE_NOT_ALLOWED"
}

def HSS_Connect(host,port,srchost,srcport):
    # Create a socket (SOCK_STREAM means a TCP socket)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((srchost, srcport))
        sock.connect((host, port))
        return sock
    except:
        hss_logger("Error in HSS Connect: %s",sys.exc_info())
        return None

def dump_Payload(avps):
    for avp in avps:
        hss_logger.debug('decoding AVP: %s',avp)
        (name,value)=decodeAVP(avp)
        if name=='EAP-Payload':
            hss_logger.debug( 'Response: %s = %s',name,value.encode('hex'))
            E=eap.decode_EAP(value.encode('hex'))
            for eavp in E.avps:
                (code,data)=eavp
                hss_logger.debug("%s = %s", code,data)
        else:
                hss_logger.debug("%s = %s", name, value)

def create_Session_Id(ORIGIN_HOST,IDENTITY):
    #The Session-Id MUST be globally and eternally unique
    #<DiameterIdentity>;<high 32 bits>;<low 32 bits>[;<optional value>]
    now=datetime.datetime.now()
    ret=ORIGIN_HOST+";"
    ret=ret+str(now.year)[2:4]+"%02d"%now.month+"%02d"%now.day
    ret=ret+"%02d"%now.hour+"%02d"%now.minute+";"
    ret=ret+"%02d"%now.second+str(now.microsecond)+";"
    ret=ret+IDENTITY[2:16]
    return ret

def create_CER(params):
    # params - dict (like Sh_params)
    # Let's build CER
    CER_avps=[]
    CER_avps.append(encodeAVP('Origin-Host', params["ORIGIN_HOST"]))
    CER_avps.append(encodeAVP('Origin-Realm', params["ORIGIN_REALM"]))
    CER_avps.append(encodeAVP('Host-IP-Address', params["SRC_HOST"]))
    CER_avps.append(encodeAVP('Vendor-Id', params["VENDOR_ID"]))
    CER_avps.append(encodeAVP('Product-Name', params["Product_Name"]))
    CER_avps.append(encodeAVP('Origin-State-Id', 0))
    CER_avps.append(encodeAVP('Supported-Vendor-Id', params["Supported_Vendor_Id"]))
    CER_avps.append(encodeAVP('Auth-Application-Id', params["APPLICATION_ID"]))
    CER_avps.append(encodeAVP('Inband-Security-Id', 0))
    CER_avps.append(encodeAVP("Vendor-Specific-Application-Id",[
             encodeAVP("Vendor-Id",params["VENDOR_ID"]),
            encodeAVP("Auth-Application-Id",params["APPLICATION_ID"])]))
    CER_avps.append(encodeAVP('Firmware-Revision',1))

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

def create_DPR(params):
    # Let's build DPR
    DPR_avps=[]
    DPR_avps.append(encodeAVP('Origin-Host', params["ORIGIN_HOST"]))
    DPR_avps.append(encodeAVP('Origin-Realm', params["ORIGIN_REALM"]))
    DPR_avps.append(encodeAVP('Host-IP-Address', params["SRC_HOST"]))
    DPR_avps.append(encodeAVP('Vendor-Id', params["VENDOR_ID"]))
    DPR_avps.append(encodeAVP('Disconnect-Cause', 'DO_NOT_WANT_TO_TALK_TO_YOU'))

    # Create message header (empty)
    DPR=HDRItem()
    # Set command code
    DPR.cmd=dictCOMMANDname2code("Disconnect-Peer")
    # Set Hop-by-Hop and End-to-End
    initializeHops(DPR)
    # Add AVPs to header and calculate remaining fields
    msg=createReq(DPR,DPR_avps)
    # msg now contains CER Request as hex string
    return msg

def diam_connect(Conn,params):
    ###########################################################
    # Let's build CER
    msg=create_CER(params)
    # msg now contains CER Request as hex string
#    logger.debug("+"*30)
    # send data
    Conn.send(msg.decode("hex"))
    # Receive response
    received = Conn.recv(MSG_SIZE)
    # split header and AVPs
    CEA=HDRItem()
    stripHdr(CEA,received.encode("hex"))
    # From CEA we needed Destination-Host and Destination-Realm
    Capabilities_avps=splitMsgAVPs(CEA.msg)
#    logger.debug ("CEA %s",Capabilities_avps)
    result_code=findAVP("Result-Code",Capabilities_avps)
    result_descr=""
    if result_code in diam_error_codes:
        result_descr=diam_error_codes[result_code]
#    logger.info ("CEA result code: %s %s", result_code, result_descr)
    hss_logger.info("CEA result code: %s %s", result_code,result_descr)
    prod_name = findAVP("Product-Name",Capabilities_avps)
    vendor = findAVP("Vendor-Id",Capabilities_avps)

    test = findAVP("TEST",Capabilities_avps)

    if (prod_name) : hss_logger.info ("Product-Name: %s",prod_name)
    if (vendor) : hss_logger.info ("Vendor: %s",vendor)

    hss_logger.debug("Capabilities AVP: %s", Capabilities_avps)
    dump_Payload(Capabilities_avps)

    return result_code

def diam_disconnect(Conn,params):
    ###########################################################
#    logger.info("Disconnecting from peer")
    # Let's build DPR
    msg=create_DPR(params)
    # msg now contains DPR Request as hex string
#    logger.debug("+"*30)
    # send data
    Conn.send(msg.decode("hex"))
    # Receive response
    received = Conn.recv(MSG_SIZE)
    # split header and AVPs
    DPA=HDRItem()
    stripHdr(DPA,received.encode("hex"))

    avps=splitMsgAVPs(DPA.msg)
#    logger.debug ("DPA %s",avps)
    result_code_dpa=findAVP("Result-Code",avps)
#    logger.info ("DPA result code: %s",result_code_dpa)
    return


def create_UDR(params,SESSION_ID,PUBLIC_IDENTITY,AVP):
    return create_REQ(params,SESSION_ID,PUBLIC_IDENTITY,AVP,"User-Data")

def create_PUR(params,SESSION_ID,PUBLIC_IDENTITY,AVP):
    return create_REQ(params,SESSION_ID,PUBLIC_IDENTITY,AVP,"Profile-Update")

def create_SNR(params,SESSION_ID,PUBLIC_IDENTITY,AVP):
    return create_REQ(params,SESSION_ID,PUBLIC_IDENTITY,AVP,"Subscribe-Notifications")

def create_REQ(params,SESSION_ID,PUBLIC_IDENTITY,AVP,CMD):

    REQ_avps=[]
    REQ_avps.append(encodeAVP("Session-Id", SESSION_ID))

    if "DEST_HOST" in params:  REQ_avps.append(encodeAVP("Destination-Host", params["DEST_HOST"]))
    if "DEST_REALM" in params: REQ_avps.append(encodeAVP("Destination-Realm", params["DEST_REALM"]))

# some requests requires MSISDN instead of public-identity, currently not
# supported
    REQ_avps.append(encodeAVP("User-Identity", [ encodeAVP("Public-Identity",PUBLIC_IDENTITY)]))

    # 1 - NO_STATE_MAINTAINED
    REQ_avps.append(encodeAVP("Auth-Session-State", 1))
    # Grouped AVPs are encoded like this
    REQ_avps.append(encodeAVP("Vendor-Specific-Application-Id",[
        encodeAVP("Vendor-Id",params["VENDOR_ID"]),
        encodeAVP("Auth-Application-Id",params["APPLICATION_ID"])]))
    REQ_avps.append(encodeAVP('Origin-Host', params["ORIGIN_HOST"]))
    REQ_avps.append(encodeAVP('Origin-Realm', params["ORIGIN_REALM"]))

    for key,value in AVP.iteritems():
        REQ_avps.append(encodeAVP(key, value))

    hss_logger.debug("REQ_avps: %s", REQ_avps)
#    logger.debug ("REQ AVPs %s",REQ_avps)
    # Create message header (empty)
    REQ=HDRItem()
    # Set command code
#    REQ.cmd=dictCOMMANDname2code("User-Data")
    REQ.cmd=dictCOMMANDname2code(CMD)
    # Set Application-Id
    REQ.appId=params["APPLICATION_ID"]
    # Set Hop-by-Hop and End-to-End
    initializeHops(REQ)
    # Set Proxyable flag
    setFlags(REQ,DIAMETER_HDR_PROXIABLE)
    # Add AVPs to header and calculate remaining fields
    msg=createReq(REQ,REQ_avps)
    # msg now contains MAR Request as hex string
    return msg

def store_pcap():

#    t=time.time()
#    ts=int(t)
#    tu=int((t-ts)*1000000)
#    p=received
#    with open('test.pcap', 'w') as f:
        # start
#        f.write(struct.pack('!IHHIIII',0xa1b2c3d4,2,4,0,0,65535,228))
        # finish
#        f.write(struct.pack('!IIII',ts,tu,len(p),len(p))+p)
    return

def diam_exec_req(Conn,msg):

#    logger.debug("+"*30)
    # send data
    Conn.send(msg.decode("hex"))

    # give a chance to HSS
    time.sleep(0.5)

    # Receive response
    received = Conn.recv(MSG_SIZE)

    #response
    RES=HDRItem()
    stripHdr(RES,received.encode("hex"))

    result_AVPs=splitMsgAVPs(RES.msg)

#    hss_logger.debug ("RES AVPs %s",result_AVPs)
    return result_AVPs

#def diam_retrive(Conn,SESSION_ID,PUBLIC_IDENTITY,UDR_AVP):
def diam_retrive(Conn,msg):

    result_AVPs=diam_exec_req(Conn,msg)

    result_code=findAVP("Result-Code",result_AVPs)
    result_descr=""
    if result_code in diam_error_codes: result_descr=diam_error_codes[result_code]
    hss_logger.info ("RES result code: %s %s", result_code, result_descr)

    user_data=parse_result(result_AVPs)

    return user_data


# act - action (udr/pur/snr)
# opt - data ref
def diam_prefill_req(act,opt):

    REQ_AVP={}

    if opt=="ALL":
        opt = ALL_SI_items
# check if opt parameter is in template list
    if opt in UDR_Template:
        REQ_AVP=UDR_Template[opt]
# if not, then request it as service-indicator
    else:
        SI_items = opt.split(',')
        hss_logger.info("SI items: %s",SI_items)

        REQ_Template={}
        REQ_Template = SNR_Template if act=='SNR' else UDR_Template

    # good place to threat notf-eff support
    # without Notif-Eff
        REQ_AVP=map(lambda SI: fill_AVP_SI(REQ_Template,SI),SI_items)

    return REQ_AVP

def fill_AVP_SI(REQ_Template,SI):
    UDR_AVP=REQ_Template["RepositoryData"].copy()
    UDR_AVP["Service-Indication"]=SI
    return UDR_AVP


def save_xml_file(filename,user_data):
    try:
        file_target = open(filename, 'w')
        file_target.write(user_data)
        file_target.close()
        hss_logger.info ("file updated")
    except:
        hss_logger.error ("filed to write into %s",filename)
    return

# read XML and returns xml.dom object
def read_xml_file(filename):
    try:
        xml_dom=xml.dom.minidom.parse(filename)
    except:
        hss_logger.error ("failed to parse xml from file %s",filename)
        return None
    return xml_dom

def parse_result(result_AVPs):
    hss_logger.debug("Result AVP: %s", result_AVPs)
    dump_Payload(result_AVPs)

    try:
        exp_result=findAVP("Experimental-Result",result_AVPs)
    except:
        hss_logger.error ("UDA no exp result")
    else:
        exp_result_descr=""
        if exp_result in diam_exp_error_codes: exp_result_descr=diam_exp_error_codes[exp_result]
        hss_logger.info ("UDA exp result code: %s %s",exp_result,exp_result_descr)

    try:
        user_data=findAVP("3GPP-User-Data",result_AVPs)
    except:
        hss_logger.error ("no userdata")
        return -1
    else:
        hss_logger.debug ("User-Data:\n%s",user_data)
        return user_data

