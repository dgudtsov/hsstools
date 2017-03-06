
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

from location_decoder import *

import logging

hss_logger = logging.getLogger('hss_tools.aux')

import os
import sys
import socket
import datetime
import time

import xml.dom.minidom

sys.path.append(pyprotosim_lib_path)
from libDiameter import *

DIAM_OK_CODE = [2001,2002]

DIAM_EXP_OK_CODE = [0,2001,2002,2003,2004]

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
2001:"DIAMETER_FIRST_REGISTRATION",                        
2002:"DIAMETER_SUBSEQUENT_REGISTRATION",                        
2003:"DIAMETER_UNREGISTERED_SERVICE",
2004:"DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED",
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

auth_types = {
    'SIP':'SIP-Digest',
    'AKA':'Digest-AKAv1-MD5',
    'NONE':'',
    "Unknown":"Unknown"
}

class Diam_request(object):
    
    REQ_AVP = dict()
    SESSION_ID=""
    CMD=None

    def __init__(self,act,OPT,AVPs,IMPU=None,IMPI=None,TEL=None):
        self.CMD = act
        
        # todo: remove from here and add AVP into constructor parameter
#        self.REQ_AVP = Templates_Cx[self.CMD].copy()
        self.REQ_AVP = AVPs
          
        if act == "MAR" :
#            self.REQ_AVP=MAR_Template.copy()
            # add auth scheme if required
            if (OPT in auth_types) & (auth_types[OPT]!=""):
                auth_AVP = [encodeAVP("3GPP-SIP-Authentication-Scheme",auth_types[OPT])]
                self.REQ_AVP["3GPP-SIP-Auth-Data-Item"] = auth_AVP
    

        for avp,value in self.REQ_AVP.iteritems():
            if type(value) is str:            
                self.REQ_AVP[avp]=value.format(IMPI=IMPI,IMPU=IMPU,TEL=TEL)    
    
        return
    
    
    def create_Session_Id(self,ORIGIN_HOST,IDENTITY):
    #The Session-Id MUST be globally and eternally unique
    #<DiameterIdentity>;<high 32 bits>;<low 32 bits>[;<optional value>]
        now=datetime.datetime.now()
        ret=ORIGIN_HOST+";"
        ret=ret+str(now.year)[2:4]+"%02d"%now.month+"%02d"%now.day
        ret=ret+"%02d"%now.hour+"%02d"%now.minute+";"
        ret=ret+"%02d"%now.second+str(now.microsecond)+";"
        ret=ret+IDENTITY[2:16]
        self.SESSION_ID = ret
        return
    
#    def create_REQ(self,params,SESSION_ID,AVP):
    def create_REQ(self,params):

        REQ_avps=[]
        REQ_avps.append(encodeAVP("Session-Id", self.SESSION_ID))
    
        if "DEST_HOST" in params:  REQ_avps.append(encodeAVP("Destination-Host", params["DEST_HOST"]))
        if "DEST_REALM" in params: REQ_avps.append(encodeAVP("Destination-Realm", params["DEST_REALM"]))
    
    # some requests requires MSISDN instead of public-identity, currently not
    # supported
    #    REQ_avps.append(encodeAVP("User-Identity", [ encodeAVP("Public-Identity",PUBLIC_IDENTITY)]))
    #    REQ_avps.append(encodeAVP("Public-Identity", PRIVATE_IDENTITY))
    
        # 1 - NO_STATE_MAINTAINED
        REQ_avps.append(encodeAVP("Auth-Session-State", 1))
        # Grouped AVPs are encoded like this
        REQ_avps.append(encodeAVP("Vendor-Specific-Application-Id",[
            encodeAVP("Vendor-Id",params["VENDOR_ID"]),
            encodeAVP("Auth-Application-Id",params["APPLICATION_ID"])]))
        REQ_avps.append(encodeAVP('Origin-Host', params["ORIGIN_HOST"]))
        REQ_avps.append(encodeAVP('Origin-Realm', params["ORIGIN_REALM"]))
    
        for key,value in self.REQ_AVP.iteritems():
            REQ_avps.append(encodeAVP(key, value))
    
        hss_logger.debug("REQ_avps: %s", REQ_avps)
        self.dump_Payload(REQ_avps)
    #    logger.debug ("REQ AVPs %s",REQ_avps)
        # Create message header (empty)
        REQ=HDRItem()
        # Set command code
    #    REQ.cmd=dictCOMMANDname2code("User-Data")

        REQ.cmd=dictCOMMANDname2code(params["CMD"][self.CMD])
        # Set Application-Id
        REQ.appId=params["APPLICATION_ID"]
        # Set Hop-by-Hop and End-to-End
        initializeHops(REQ)
        # Set Proxyable flag
        setFlags(REQ,DIAMETER_HDR_PROXIABLE)
        # Add AVPs to header and calculate remaining fields
        msg=createReq(REQ,REQ_avps)
        # msg now contains MAR Request as hex string
        self.msg = msg
        return

    def dump_Payload(self,avps):
        for avp in avps:
            hss_logger.debug('decoding AVP: %s',avp)
            (name,value)=decodeAVP(avp)
            if name!='EAP-Payload':
                    hss_logger.debug("%s = %s", name, value)

class Diam_response(object):
    
    result_AVPs=None
    result_code = 0
    result_descr = ""
    exp_result_code = 0
    exp_result_descr =""
    
    def __init__(self,result):
        self.result_AVPs = result 
        
    def get_result_code(self):
        self.result_code=findAVP("Result-Code",self.result_AVPs)
        return self.result_code
        
    def get_exp_result_code(self):

        exp_result_AVP = findAVP("Experimental-Result",self.result_AVPs)
        if exp_result_AVP != -1:
            exp_result = dict(exp_result_AVP)
            
            self.exp_result_code = exp_result['Experimental-Result-Code']
        return self.exp_result_code
    
#            hss_logger.warning ("RES exp result code: %s %s",exp_result_code,exp_result_descr)
           
    def get_exp_result_descr(self):
        self.exp_result_descr = diam_exp_error_codes.get(self.exp_result_code,"")
        return self.exp_result_descr
    
    def get_result_descr(self):
        self.result_descr = diam_error_codes.get(self.result_code,"")
        return self.result_descr
    
    def get_Cx_server_name(self):
        server_name=""
#        print self.result_code
#        print self.exp_result_code        
        if (self.result_code>0)|(self.exp_result_code in DIAM_EXP_OK_CODE):
            server_name=findAVP("Server-Name",self.result_AVPs)
        else:
            serv_cap_avp=findAVP("Server-Capabilities",self.result_AVPs)
            if serv_cap_avp != -1:
                serv_cap = dict(serv_cap_avp)
                server_name=serv_cap["Server-Name"]
        return server_name
        
# returns Result-Code if any
    def print_result(self):
        result_code=findAVP("Result-Code",self.result_AVPs)
        if result_code != -1:
            result_descr=""
            if result_code in diam_error_codes: result_descr=diam_error_codes[result_code]
            hss_logger.info ("RES result code: %s %s", result_code, result_descr)
    
            if result_code in DIAM_OK_CODE:
                hss_logger.debug("DIAM_OK!")
    
    # result code is present, returning it
            return result_code
        else:
            exp_result_AVP = findAVP("Experimental-Result",self.result_AVPs)
            if exp_result_AVP != -1:
                exp_result = dict(exp_result_AVP)
                exp_result_code = exp_result['Experimental-Result-Code']
    
                exp_result_descr=""
                if (exp_result_code!=0)&(exp_result_code in diam_exp_error_codes): exp_result_descr=diam_exp_error_codes[exp_result_code]
                hss_logger.warning ("RES exp result code: %s %s",exp_result_code,exp_result_descr)
    
    # result-code doesn't exist, return nothing
        return
    
    def parse_result(self):
        hss_logger.debug("Result AVP: %s", self.result_AVPs)
        self.dump_Payload()
        exp_result_code = 0
    
        try:
            exp_result_AVP = findAVP("Experimental-Result",self.result_AVPs)
            if exp_result_AVP != -1:
                exp_result = dict(exp_result_AVP)
                exp_result_code = exp_result['Experimental-Result-Code']
        except:
            hss_logger.error ("UDA no exp result")
        else:
            exp_result_descr=""
            if (exp_result_code!=0)&(exp_result_code in diam_exp_error_codes): exp_result_descr=diam_exp_error_codes[exp_result_code]
            hss_logger.info ("UDA exp result code: %s %s",exp_result_code,exp_result_descr)
    
        try:
            user_data=findAVP("3GPP-User-Data",self.result_AVPs)
            if user_data == -1:
                user_data=findAVP("User-Data",self.result_AVPs)
                if user_data == -1:
                    hss_logger.error ("no userdata")
                    return -1
    
        except:
            hss_logger.error ("no userdata")
            return -1
        else:
            # remove xml formating
            user_data = user_data.replace('\n', '').replace('\r', '')
            hss_logger.debug ("User-Data:\n%s",user_data)
            return user_data

    def dump_Cx_response(self):
        for avp in self.result_AVPs:
            hss_logger.debug('decoding AVP: %s',avp)
            (name,value)=decodeAVP(avp)
            if name in ["3GPP-SIP-Auth-Data-Item"]:
                hss_logger.info("%s = %s", name, value)
    
    
    def dump_Payload(self):
        for avp in self.result_AVPs:
            hss_logger.debug('decoding AVP: %s',avp)
            (name,value)=decodeAVP(avp)
            if name!='EAP-Payload':
                    hss_logger.debug("%s = %s", name, value)
    

class Diam_userdata(object):
    
    user_data = None
    xml_dom = None
    
    def __init__(self,user_data):
        self.user_data = user_data
        return
    
    def print_pretty_xml(self):
        hss_logger.info("Printing pretty XML:")
        try:
            xml_dom=xml.dom.minidom.parseString(self.user_data)
            pretty_xml=xml_dom.toprettyxml(indent=" "*2)
    #        pretty_xml=xml_dom.toprettyxml()
            hss_logger.info( pretty_xml )
            # check that xml contains CS Location information inside
            if (xml_dom.getElementsByTagName("CSLocationInformation")):
                hss_logger.info( "cs location decoding")

                L = Location(xml_dom)                
                L.loc_dump()

    
            xml_dom.unlink()
        except:
            hss_logger.error("can't pretty format xml %s",sys.exc_info())
        return

    def save_xml_file(self,filename):
    
        full_filename = DATA_FILE.format(SI = filename)
    
        try:
            file_target = open(full_filename, 'w')
            file_target.write(self.user_data)
            file_target.close()
            hss_logger.info ("file updated")
        except:
            hss_logger.error ("filed to write into %s",filename)
        return
    
    # read XML and returns xml.dom object
    # stores xml_dom object into self
    def read_xml_file(self,filename):
    
        full_filename = DATA_FILE.format(SI = filename)
    
        try:
            xml_dom=xml.dom.minidom.parse(full_filename)
        except:
            hss_logger.error ("failed to parse xml from file %s : %s",filename,sys.exc_info())
            return None
        self.xml_dom = xml_dom
        return True

    def xml_get_seq(self):
        xml_dom=xml.dom.minidom.parseString(self.user_data)
        seq=xml_dom.getElementsByTagName("SequenceNumber")[0].firstChild.nodeValue
        return int(seq)
    
# takes xml.dom object and updates Node with new seq value
# returns string
    def xml_update_seq(self,seq):
        self.xml_dom.getElementsByTagName("SequenceNumber")[0].firstChild.nodeValue=seq
        return self.xml_dom.toxml()
    
    def dump(self):
        return self.xml_dom.toxml().replace('\n','')

class HSS(object):
    
    sock=None
    
    params=dict()
    
    def __init__(self,params):
            # Create a socket (SOCK_STREAM means a TCP socket)
        
        self.params = params
        
        host = params["HOST"]
        port = params["PORT"]
        src_host = params.get("SRC_HOST",None)
        src_port = params.get("SRC_PORT",None)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if ((src_host!=None) & (src_port!=None)):
                sock.bind((src_host, src_port))
            sock.connect((host, port))
            self.sock = sock
        except:
            hss_logger.error("Error in HSS Connect: %s",sys.exc_info())
            return 1
        return
    
    def connect(self):
   
        ###########################################################
        # Let's build CER
        msg=self.create_CER(self.params)
        # msg now contains CER Request as hex string
    #    logger.debug("+"*30)
    
        try:
            # send data
            self.sock.send(msg.decode("hex"))
            # Receive response
            received = self.sock.recv(MSG_SIZE)
        except:
            hss_logger.error("diam connection exception: %s",sys.exc_info())
            return None
    
    
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
    
    #    vendor_app_id = findAVP("Vendor-Specific-Application-Id",Capabilities_avps)
    #    auth_app_id = findAVP("Auth-Application-Id",vendor_app_id)
    
#        test = findAVP("TEST",Capabilities_avps)
    
        if (prod_name) : hss_logger.info ("Product-Name: %s",prod_name)
        if (vendor) : hss_logger.info ("Vendor: %s",vendor)
    #    if (auth_app_id): hss_logger.info ("App id: %s",auth_app_id)
    
        hss_logger.debug("Capabilities AVP: %s", Capabilities_avps)
        self.dump_Payload(Capabilities_avps)
    
        return result_code   
   
    
    def create_CER(self,params):
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
    
        hss_logger.debug("CER AVP: %s", CER_avps)
        
        self.dump_Payload(CER_avps)
    
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

    def create_DPR(self,params):
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

    def diam_retrive(self,Diam_request):
    
        result_AVPs=self.diam_exec_req(Diam_request)
        
        response = Diam_response(result_AVPs)
    
        result_code=findAVP("Result-Code",result_AVPs)
        result_descr=""
        if result_code in diam_error_codes: result_descr=diam_error_codes[result_code]
        hss_logger.info ("RES result code: %s %s", result_code, result_descr)
        
        user_data = -1
        if result_code in DIAM_OK_CODE:
#        user_data=parse_result(result_AVPs)
            user_data = response.parse_result()
    
        return user_data

    def diam_exec_req(self,Diam_request):
    
    #    logger.debug("+"*30)
    
        try:
            # send data
            self.sock.send(Diam_request.msg.decode("hex"))
        except:
            hss_logger.error("diam connection exception: %s",sys.exc_info())
            return None
    
        # give a chance to HSS
        time.sleep(0.5)
    
        try:
            # Receive response
            received = self.sock.recv(MSG_SIZE)
        except:
            hss_logger.error("diam connection exception: %s",sys.exc_info())
            return None
    
        #response
        RES=HDRItem()
        stripHdr(RES,received.encode("hex"))
    
        result_AVPs=splitMsgAVPs(RES.msg)
    
        cmd = dictCOMMANDcode2name(RES.flags, RES.cmd)
        hss_logger.debug("CMD code: %s", cmd)
    
    #    hss_logger.debug ("RES AVPs %s",result_AVPs)
        return result_AVPs

    def disconnect(self,params):
        ###########################################################
    #    logger.info("Disconnecting from peer")
        # Let's build DPR
        msg=self.create_DPR(params)
        # msg now contains DPR Request as hex string
    #    logger.debug("+"*30)
        # send data
        self.sock.send(msg.decode("hex"))
        # Receive response
        received = self.sock.recv(MSG_SIZE)
        # split header and AVPs
        DPA=HDRItem()
        stripHdr(DPA,received.encode("hex"))
    
        avps=splitMsgAVPs(DPA.msg)
    #    logger.debug ("DPA %s",avps)
        result_code_dpa=findAVP("Result-Code",avps)
    #    logger.info ("DPA result code: %s",result_code_dpa)
    # And close the connection
        self.sock.close()
        return

    def dump_Payload(self,avps):
        for avp in avps:
            hss_logger.debug('decoding AVP: %s',avp)
            (name,value)=decodeAVP(avp)
            if name!='EAP-Payload':
                    hss_logger.debug("%s = %s", name, value)




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


#def diam_retrive(Conn,SESSION_ID,PUBLIC_IDENTITY,UDR_AVP):



# act - action (udr/pur/snr)
# opt - data ref
def diam_prefill_req(act,opt,IMPU=None,IMPI=None):

    REQ_AVP = {}

    if act in ['SNR', 'UDR', 'PUR']:

        if opt=="ALL":
            opt = ALL_SI_items
    # check if opt parameter is in template list
    # like Location, etc...
    
    # if SINGLE SI
        if opt in UDR_Template:
            REQ_AVP=UDR_Template[opt]
        # add IMPU
            REQ_AVP[0]["User-Identity"] = [ encodeAVP("Public-Identity",IMPU) ]

    # if not, then request it as service-indicator
    # => Repository Data
    
    # in case of multiple SI
        else:
            SI_items = opt.split(',')
            hss_logger.info("SI items: %s",SI_items)

            REQ_Template={}
            REQ_Template = SNR_Template if act=='SNR' else UDR_Template
            REQ_Template["RepositoryData"]["User-Identity"] = [ encodeAVP("Public-Identity",IMPU) ]

        # good place to threat notf-eff support
        # without Notif-Eff
            REQ_AVP=map(lambda SI: fill_AVP_SI(REQ_Template,SI),SI_items)

    return REQ_AVP

def fill_AVP_SI(REQ_Template,SI):
    UDR_AVP=REQ_Template["RepositoryData"].copy()
    UDR_AVP["Service-Indication"]=SI
    return UDR_AVP





