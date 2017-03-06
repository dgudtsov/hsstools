#!/usr/bin/python
# Absolutely minimum python version is 2.6.6!

# HSS Tools

##################################################################
# Copyright (c) 2015-2017 Denis Gudtsov
# License - GPL
# https://github.com/dgudtsov/hsstools
#
# based on  Python Protocol Simulator project
# https://sourceforge.net/projects/pyprotosim/
##################################################################

import logging
import logging.handlers
# due to bad logging handling in pyprotosim module
logging.basicConfig(level=logging.CRITICAL,filename="/dev/null")

import sys

sys.path.append("./conf")
sys.path.append("./lib")

from config_diam import *
from hss_tools import *
from location_decoder import *

# key to connection params, is used for log filename as well
params_key="Sh"
# link to dict defined in hss_tools module
params=conn_params[params_key]

# now all options accessible by direct keys like:
# params["HOST"]


########## LOGGING ###########

logger = logging.getLogger('hss_tools')
logger.setLevel(logging.DEBUG)

# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)

LOG_FILENAME = LOG.format(module=params_key)

fh = logging.FileHandler(LOG_FILENAME)
fh.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(name)s:%(levelname)s: %(message)s')
ch.setFormatter(formatter)
fh.setFormatter(formatter)

rotate = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=LOG_size, backupCount=LOG_count)
rotate.setLevel(logging.DEBUG)

rotate.setFormatter(formatter)

logger.addHandler(ch)
#logger.addHandler(fh)
logger.addHandler(rotate)


########## LOGGING END ###########

sys.path.append("..")
sys.path.append(pyprotosim_lib_path)

from libDiameter import *
import eap
import datetime
import time
import sys
import xml.dom.minidom


########## HELP OUTPUT ###########

HELP = """
Format: {APP_NAME} COMMAND IMSI MSISDN DATA
COMMAND: one of UDR, PUR, SNR
MSISDN: msisdn of the subscriber, without +
DATA: Data-reference name OR Service-Indicator name of repository data
DATA possible values are: {UDR}
Examples:
- to read data
example: {APP_NAME} UDR 250000000000000 79999999999 MMTEL-Services
example: {APP_NAME} UDR 250000000000000 79999999999 MMTEL-Services,IMS-CAMEL-Services
example: {APP_NAME} UDR 250000000000000 79999999999 ALL
example: {APP_NAME} UDR 250000000000000 79999999999 Location
example: {APP_NAME} UDR 250000000000000 79999999999 TADS
ALL means: {ALL_SI}
- to update data
example: {APP_NAME} PUR 250000000000000 79999999999 MMTEL-Services
"""

########## HELP END ###########

########## VOID MAIN ###########

if __name__ == "__main__":
    logger.info('%s is started: %s',sys.argv[0], sys.argv[1:])
    logger.debug('Number of arguments: %s arguments.', len(sys.argv))
    if len(sys.argv)<4:
        logger.debug("program started with empty parameters")
        print HELP.format(APP_NAME = sys.argv[0], UDR = UDR_Template.keys(), ALL_SI = ALL_SI_items)
        logger.debug("exiting")
        exit()

    LoadDictionary(pyprotosim_dict_path+"/dictDiameter.xml")
    eap.LoadEAPDictionary(pyprotosim_dict_path+"/dictEAP.xml")

    # ACTION: UDR / PUR / SNR
    # OPT: Service-Indicator or Data-Reference
    (ACTION,MSISDN,OPT) = sys.argv[1:4]
    
#    ACTION = sys.argv[1]

#    IMSI = sys.argv[2]
#    MSISDN = sys.argv[3]

    IMSI = MSISDN
    
#    OPT = sys.argv[4]

#    PUBLIC_IDENTITY=params["IMPU_format"].format(IDENTITY = IDENTITY,IMPU_domain = params["IMPU_domain"] )
    
    IMPU=params["IMPU_format"].format(IDENTITY = MSISDN,IMPU_domain = params["IMPU_domain"] )
    IMPI=params["IMPI_format"].format(IDENTITY = IMSI,IMPI_domain = params["IMPI_domain"] )
    TEL=params["TEL_format"].format(IDENTITY = MSISDN)
    
    logger.info("IMPI ident: %s", IMPI)
    logger.info("IMPU ident: %s", IMPU)
    logger.info("TEL: %s", TEL)

    
#    IMPI = IDENTITY+params["IMPI_domain"]

#    logger.info("public ident: %s", PUBLIC_IDENTITY)
#    logger.info("IMPI ident: %s", IMPI)

    # for summary report
    summary = {}

    if ACTION in ['UDR','PUR', 'SNR']:
        config_dump()
    # UDR action should precede PUR
        UDR_AVPs=diam_prefill_req(ACTION,OPT,IMPU=IMPU)
        logger.info("prefilled request: %s", UDR_AVPs)

        Conn = HSS(params)

        if (Conn):
            logger.info("HSS IP connectivity established")
            # CER/CEA
#            CEA_result=diam_connect(Conn,params)
            CEA_result=Conn.connect()
            
            if CEA_result in DIAM_OK_CODE:

#                for UDR_AVP in Diam_AVPs.REQ_AVP:
                for UDR_AVP in UDR_AVPs:
                    if "Service-Indication" in UDR_AVP:
                        # mark unsupported by default
                        summary[UDR_AVP["Service-Indication"]] = False

                    Diam_AVPs = Diam_request("UDR" if ACTION == "PUR" else ACTION,OPT,UDR_AVP,IMPI=IMPI,IMPU=IMPU,TEL=TEL)

                    Diam_AVPs.create_Session_Id(params["ORIGIN_HOST"],IMSI)
                    logger.info("Session ID: %s", Diam_AVPs.SESSION_ID)
                    logger.info("preparing %s", "UDR" if ACTION == "PUR" else ACTION)
                    logger.info("requesting %s", UDR_AVP )
                    
                    Diam_AVPs.create_REQ(params)
                    
                    result_AVPs = Conn.diam_exec_req(Diam_AVPs)
                    response = Diam_response(result_AVPs)
                    result_code = response.get_result_code()

                    if result_code>0:
                        result_descr = response.get_result_descr()
                        logger.info ("RES result code: %s %s", result_code, result_descr)
                        exp_result_code=0
                    else:
                        exp_result_code = response.get_exp_result_code()
                        exp_result_descr = response.get_exp_result_descr()
                        logger.info ("Exp RES result code: %s %s", exp_result_code, exp_result_descr)
                
                    response.dump_Payload()
                   
                    user_data=Conn.diam_retrive(Diam_AVPs)                    

                    if ACTION == 'UDR':
                        
                        if (user_data!=-1):
                            if len(user_data)>10:
                                
                                if "Service-Indication" in UDR_AVP:  summary[UDR_AVP["Service-Indication"]] = True
                                
                                UD = Diam_userdata(user_data)
                                if PRINT_PRETTY_XML:
                                    UD.print_pretty_xml()
                        
                                    try:
                                        filename=UDR_AVP["Service-Indication"]
                                        logger.info ("writing userdata into file: %s",filename)
                                        UD.save_xml_file(filename)
                                    except:
                                        pass
        #                                logger.error ("failed to save userdata into file")
                    elif ACTION == 'PUR':
                        logger.info("Preparing update")
                        try:
                            # trying to load data from file
                            filename=UDR_AVP["Service-Indication"]
                            
                            UD_new = Diam_userdata(None)
                            xml_profile_result = UD_new.read_xml_file(filename)

                        except:
                            logger.error("loading data from file %s failed",filename)
                        else:
                            # retrive current seq number from previous UDR req
                            if (user_data!=-1):
                            # then seq > 0
                                UD_old = Diam_userdata(user_data)
                                sequence_num=UD_old.xml_get_seq()+1
                            else:
                                sequence_num=0
                            logger.info("new sequence number for subscriber profile = %s",sequence_num)

                            PUR_AVP=UDR_AVP.copy()
                            
                            if (xml_profile_result):
                                UD_new.xml_update_seq(sequence_num)

                                logger.info ("UD: "+UD_new.dump())
                                PUR_AVP["3GPP-User-Data"]=str(UD_new.dump())

                                
                                logger.debug("PUR AVP: %s",PUR_AVP)
                                
                                Diam_AVPs_PUR = Diam_request(ACTION,OPT,PUR_AVP,IMPI=IMPI,IMPU=IMPU,TEL=TEL)
                                Diam_AVPs_PUR.create_Session_Id(params["ORIGIN_HOST"],IMSI)
                                
                                Diam_AVPs_PUR.create_REQ(params)
                                
                                result_AVPs = Conn.diam_exec_req(Diam_AVPs_PUR)
                                
                                response = Diam_response(result_AVPs)
                                result_code = response.get_result_code()                                

                                if (response.print_result() in DIAM_OK_CODE):
                                        summary[UDR_AVP["Service-Indication"]] = True

                                response.dump_Payload()

                ###########################################################
                # Disconnecting peer
                Conn.disconnect(params)

        else:
            logger.error("can't connect to HSS %s:%s",params["HOST"],params["PORT"])
    else:
        print "Only UDR, SNR or PUR actions are supported"
        logger.info("wrong action selected, exiting")
        exit()
    logger.info("Summary:")
    for key,value in summary.iteritems():
        logger.info(" - {0:30} :  {1:5}".format(key,value))

    logger.info("End")
    exit()
### PROGRAM END
