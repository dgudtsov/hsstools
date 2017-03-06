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
params_key="Cx"
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
Format: {APP_NAME} COMMAND IMSI MSISDN [AUTH]
COMMAND: MAR, UAR, SAR, LIR
IMSI: imsi of the subscriber
MSISDN: msisdn of the subscriber
AUTH (optional, only for MAR is required): SIP, AKA, NONE, Unknown

IMPI and IMPU are constructed from IMSI/MSISDN

Examples:
- to request SIP-Digest auth scheme
example: {APP_NAME} MAR 250009999999999 1234567 SIP

- to request Digest-AKA auth scheme
example: {APP_NAME} MAR 250009999999999 1234567 AKA

- to allow HSS select default auth scheme
example: {APP_NAME} MAR 250009999999999 1234567 Unknown
"""

########## HELP END ###########

########## VOID MAIN ###########

if __name__ == "__main__":
    logger.info('%s is started: %s',sys.argv[0], sys.argv[1:])
    logger.debug('Number of arguments: %s arguments.', len(sys.argv))
    if len(sys.argv)<3:
        logger.debug("program started with empty parameters")
        print HELP.format(APP_NAME = sys.argv[0], UDR = UDR_Template.keys(), ALL_SI = ALL_SI_items)
        logger.debug("exiting")
        exit()

    LoadDictionary(pyprotosim_dict_path+"/dictDiameter.xml")
    eap.LoadEAPDictionary(pyprotosim_dict_path+"/dictEAP.xml")

    # ACTION: MAR
    ACTION = sys.argv[1]

    IMSI = sys.argv[2]
    MSISDN = sys.argv[3]
    # IDENTITY: MSISDN
#    IDENTITY = sys.argv[2]

    # OPT: SIP/AKA/NONE
    if ACTION in ['MAR']:
        if len(sys.argv)<5:
            logger.error('AUTH param is missing')
            exit()
        OPT = sys.argv[4]
    else:
        OPT = None

#    PUBLIC_IDENTITY="sip:+"+IDENTITY+params["IMPU_domain"]
#    IMPI = IDENTITY+params["IMPI_domain"]

#    PUBLIC_IDENTITY=params["IMPU_format"].format(IDENTITY = IDENTITY,IMPU_domain = params["IMPU_domain"] )

    IMPU=params["IMPU_format"].format(IDENTITY = MSISDN,IMPU_domain = params["IMPU_domain"] )
    IMPI=params["IMPI_format"].format(IDENTITY = IMSI,IMPI_domain = params["IMPI_domain"] )
    TEL=params["TEL_format"].format(IDENTITY = MSISDN)
    
    logger.info("IMPI ident: %s", IMPI)
    logger.info("IMPU ident: %s", IMPU)
    logger.info("TEL: %s", TEL)
    

    # for summary report
    summary = {}

    if ACTION in ['MAR','SAR', 'LIR', 'UAR']:
        config_dump(params_key)
        
        AVPs = Templates[params_key][ACTION].copy()
        print AVPs
        
        Diam_AVPs = Diam_request(ACTION,OPT,AVPs,IMPI=IMPI,IMPU=IMPU,TEL=TEL)
        Diam_AVPs.REQ_AVP["Server-Name"] = params["Server-Name"]
        
        logger.info("prefilled request: %s", Diam_AVPs.REQ_AVP)

        Conn = HSS(params)
        if (Conn):
            logger.info("HSS IP connectivity established")
            # CER/CEA

            CEA_result=Conn.connect()
            if CEA_result in DIAM_OK_CODE:

                Diam_AVPs.create_Session_Id(params["ORIGIN_HOST"],IMSI)
                
                logger.info("Session ID: %s", Diam_AVPs.SESSION_ID)

                logger.info("preparing %s",ACTION)
                
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
                            
                if ACTION == "MAR":
                    # dump auth part
                    response.dump_Cx_response()

                elif ACTION == "SAR":

                    user_data=Conn.diam_retrive(Diam_AVPs)
                    
                    if result_code in DIAM_OK_CODE:
                        user_data = response.parse_result()
                    
                        if (user_data!=-1):
                            if len(user_data)>10:
    #                                logger.info(UDR_AVP)
                                UD = Diam_userdata(user_data)
                                if PRINT_PRETTY_XML:
                                    UD.print_pretty_xml()
                            try:
                                filename=SAR_FileName
                                logger.info ("writing userdata into file: %s",filename)
                                UD.save_xml_file(filename)
    #                            save_xml_file(filename,user_data)
                            except:
                                pass
#                            logger.error ("failed to save userdata into file")
                elif ACTION in ('LIR','UAR'):
                    if (not result_code in diam_error_codes)&(exp_result_code in DIAM_EXP_OK_CODE ):
                        server_name = response.get_Cx_server_name()
                        logger.info ("Server Name: %s", server_name)
                    
                ###########################################################
                # Disconnecting peer
                Conn.disconnect(params)
                # And close the connection
#                Conn.close()
        else:
            logger.error("can't connect to HSS %s:%s",params["HOST"],params["PORT"])
    else:
        print "Only MAR, SAR, LIR, UAR actions are supported"
        logger.info("wrong action selected, exiting")
        exit()

    logger.info("End")
    exit()
### PROGRAM END
