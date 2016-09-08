#!/usr/bin/python
# Absolutely minimum python version is 2.6.6!

# HSS Tools

##################################################################
# Copyright (c) 2015-2016 Denis Gudtsov
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
Format: {APP_NAME} COMMAND MSISDN DATA
COMMAND: one of UDR, PUR, SNR
MSISDN: msisdn of the subscriber, without +
DATA: Data-reference name OR Service-Indicator name of repository data
DATA possible values are: {UDR}
Examples:
- to read data
example: {APP_NAME} UDR 79999999999 MMTEL-Services
example: {APP_NAME} UDR 79999999999 MMTEL-Services,IMS-CAMEL-Services
example: {APP_NAME} UDR 79999999999 ALL
example: {APP_NAME} UDR 79999999999 Location
example: {APP_NAME} UDR 79999999999 TADS
ALL means: {ALL_SI}
- to update data
example: {APP_NAME} PUR 79999999999 MMTEL-Services
"""

########## HELP END ###########


########## FUNCTIONS ###########

def xml_get_seq(xml_doc):
    xml_dom=xml.dom.minidom.parseString(xml_doc)
    seq=xml_dom.getElementsByTagName("SequenceNumber")[0].firstChild.nodeValue
    return int(seq)

# takes xml.dom object and updates Node with new seq value
def xml_update_seq(xml_dom,seq):
    xml_dom.getElementsByTagName("SequenceNumber")[0].firstChild.nodeValue=seq
    return xml_dom.toxml()

def print_pretty_xml(xml_str):
    logger.info("Printing pretty XML:")
    try:
        xml_dom=xml.dom.minidom.parseString(xml_str)
        pretty_xml=xml_dom.toprettyxml(indent=" "*2)
#        pretty_xml=xml_dom.toprettyxml()
        logger.info( pretty_xml )
        # check that xml contains CS Location information inside
        if (xml_dom.getElementsByTagName("CSLocationInformation")):
            logger.info( "cs location decoding")
            loc_dump(xml_dom)

        xml_dom.unlink()
    except:
        logger.error("can't pretty format xml %s",sys.exc_info())
    return

########## END FUNCTIONS ###########

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
    ACTION = sys.argv[1]

    # IDENTITY: MSISDN
    IDENTITY = sys.argv[2]

    # OPT: Service-Indicator or Data-Reference
    OPT = sys.argv[3]

#    PUBLIC_IDENTITY="sip:+"+IDENTITY+params["IMPU_domain"]
    PUBLIC_IDENTITY=params["IMPU_format"].format(IDENTITY = IDENTITY,IMPU_domain = params["IMPU_domain"] )
#    IMPI = IDENTITY+params["IMPI_domain"]

    logger.info("public ident: %s", PUBLIC_IDENTITY)
#    logger.info("IMPI ident: %s", IMPI)

    # for summary report
    summary = {}

    if ACTION in ['UDR','PUR', 'SNR']:
        config_dump()
    # UDR action should precede PUR
        UDR_AVPs=diam_prefill_req(ACTION,OPT,IMPU=PUBLIC_IDENTITY)
        logger.info("prefilled request: %s", UDR_AVPs)

        Conn=HSS_Connect(params["HOST"],params["PORT"],params["SRC_HOST"],params["SRC_PORT"])
        if (Conn):
            logger.info("HSS IP connectivity established")
            # CER/CEA
            CEA_result=diam_connect(Conn,params)
            if CEA_result in DIAM_OK_CODE:

                for UDR_AVP in UDR_AVPs:
                    if "Service-Indication" in UDR_AVP:
                        # mark unsupported by default
                        summary[UDR_AVP["Service-Indication"]] = False

                    SESSION_ID=create_Session_Id(params["ORIGIN_HOST"],IDENTITY)
                    logger.info("Session ID: %s", SESSION_ID)

                    logger.info("requesting %s", UDR_AVP )

#                    msg=create_SNR(params,SESSION_ID,PUBLIC_IDENTITY,UDR_AVP) if ACTION=='SNR' else create_UDR(params,SESSION_ID,PUBLIC_IDENTITY,UDR_AVP)
                    msg=create_SNR(params,SESSION_ID,UDR_AVP) if ACTION=='SNR' else create_UDR(params,SESSION_ID,UDR_AVP)
                    user_data=diam_retrive(Conn,msg)
    #                user_data=diam_retrive(Conn,SESSION_ID,PUBLIC_IDENTITY,UDR_AVP)
                    if ACTION == 'UDR':
                        if (user_data!=-1):
                            if len(user_data)>10:
#                                logger.info(UDR_AVP)
                                if "Service-Indication" in UDR_AVP:  summary[UDR_AVP["Service-Indication"]] = True
                                if PRINT_PRETTY_XML:
                                    print_pretty_xml(user_data)
                            try:
                                filename=UDR_AVP["Service-Indication"]
                                logger.info ("writing userdata into file: %s",filename)
                                save_xml_file(filename,user_data)
                            except:
                                pass
#                                logger.error ("failed to save userdata into file")
                    elif ACTION == 'PUR':
                        logger.info("Preparing update")
                        try:
                            # trying to load data from file
                            filename=UDR_AVP["Service-Indication"]

                            # xml_profile - xml.dom document
                            xml_profile = read_xml_file(filename)
                        except:
                            logger.error("loading data from file %s failed",filename)
                        else:
                            # retrive current seq number
                            if (user_data!=-1)&(len(user_data)>10):
                            # then seq > 0
                                sequence_num=xml_get_seq(user_data)+1
                            else:
                                sequence_num=0
                            logger.info("new sequence number for subscriber profile = %s",sequence_num)

                            PUR_AVP=UDR_AVP.copy()
                            UD=""
                            if (xml_profile): UD=xml_update_seq(xml_profile,sequence_num)
                            logger.info ("UD: "+UD.replace('\n',''))
                            PUR_AVP["3GPP-User-Data"]=str(UD.replace('\n',''))
                            logger.debug("PUR AVP: %s",PUR_AVP)

#                            msg=create_PUR(params,SESSION_ID,PUBLIC_IDENTITY,PUR_AVP)
                            msg=create_PUR(params,SESSION_ID,PUR_AVP)
                            user_data=diam_retrive(Conn,msg)

                ###########################################################
                # Disconnecting peer
                diam_disconnect(Conn,params)
                # And close the connection
                Conn.close()
        else:
            logger.error("can't connect to HSS %s:%s",params["HOST"],params["PORT"])
    else:
        print "Only UDR, SNR or PUR actions are supported currently"
        logger.info("wrong action selected, exiting")
        exit()
    logger.info("Summary:")
    for key,value in summary.iteritems():
        logger.info(" - {0:30} :  {1:5}".format(key,value))

    logger.info("End")
    exit()
### PROGRAM END
