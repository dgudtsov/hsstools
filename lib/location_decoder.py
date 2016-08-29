#!/usr/bin/python


# CS Location decoder module for HSS Tools

##################################################################
# Copyright (c) 2015-2016 Denis Gudtsov
# License - GPL
# https://github.com/dgudtsov/hsstools
##################################################################


import logging
decoder_logger = logging.getLogger('hss_tools.loc_decoder')


import base64
import xml.dom.minidom
import sys

sys.path.append("../conf")

from config_diam import *

# force_swap = True - apply BCD to all digits in string (vlr decode)
# if False, then apply only to mnc&mcc (location decode)
def loc_decode(src_str,force_swap=False):
    # len in bytes (two digits per one byte)
    mcc_mnc_len=6/2
    lai_len=4/2
#    print "loc_decode ",src_str
    decoded_str = base64.b64decode(src_str)
#    print "raw decoded ",decoded_str
#    print "base64 decoded (dec): "+(" ".join([str(ord(c)) for c in decoded_str]))
#    print "base64 decoded (hex): "+(" ".join(['{0:02x}'.format(ord(c)) for c in decoded_str]))
    decoder_logger.debug("base64 decoded (hex): %s ", (" ".join(['{0:02x}'.format(ord(c)) for c in decoded_str])))

    result = ""
    for idx,char in enumerate(decoded_str):
        digit1,digit2 = ord(char) & 0xf , ord(char) >> 4 & 0xf
        # swap bytes after mnc/mcc
        for b in ([digit1,digit2] if ((idx<mcc_mnc_len)|force_swap) else [digit2, digit1]):
            result += '{0:x}'.format(b)

# pretty formating output
    if force_swap:
        decoder_logger.info( "result: %s",result)
    else:
        # 6=mcc/mnc len, 4=lai len
#        print "result (MCC|MNC_LAI_CGI): "+'{0:_<7.6}'.format(result) + '{0:_<5.4}'.format(result[6:]) + result[10:]
#        print "result (MCC|MNC_LAI_CGI): "+'{0:<6.6}_{1:<4.4}_{2}'.format(result, result[6:],result[10:])
        decoder_logger.info( "result (MCC|MNC_LAI_CGI): %s",'{0:<6.6}_{1:<4.4}_{2}'.format(result, result[6:],result[10:]))

    return result

# xml_dom - xml.dom.minidom object
# document must not contain \n symbols!
def loc_dump(xml_dom):

    for location_item in CSLocation_Elements:
#        print "decoding ",location_item
        element = xml_dom.getElementsByTagName(location_item)
        if element:
            child = element[0].childNodes[0]
            node_type = child.nodeType
            if node_type == child.TEXT_NODE:
#            child_nodes = len(element[0].childNodes)
#            print "child nodes: ",child_nodes
            # true for location data
#            if child_nodes == 1 :
                value=element[0].firstChild.nodeValue
#                print value
#                print location_item,value, loc_decode(value)
                decoder_logger.info ("decoding %s",location_item)
                decoder_logger.info ("%s %s %s",location_item,value, loc_decode(value))
            # true for msc/vlr data
#            elif child_nodes >1 :
            elif node_type == child.ELEMENT_NODE:
#                for ch in element[0].childNodes:
#                    print ch.nodeType, ch.nodeName
#                    if (ch.nodeType==ch.ELEMENT_NODE) & (ch.nodeName=='Address'):
#                        child=ch
#                        break
                value=child.firstChild.nodeValue
#                print location_item, value , loc_decode(value,True)
                decoder_logger.info ("decoding %s",location_item)
                decoder_logger.info ("%s %s %s", location_item, value , loc_decode(value,True))
    return


# test

if __name__ == "__main__":

    xml_data="""<?xml version="1.0" encoding="UTF-8"?>
    <Sh-Data>
    <CSLocationInformation>
    <LocationNumber>hJdHWQI=</LocationNumber>
    <LocationAreaId>UvACbLQ=</LocationAreaId>
    <ServiceAreaId>
	UvACbMDw5Q==
    </ServiceAreaId>
    <VLRNumber>
    <Address>kZd3UpMA8Q==</Address>
    </VLRNumber>
    <MSCNumber>
    <Address>kZd3UpMA8Q==</Address>
    </MSCNumber>
    <AgeOfLocationInformation>55</AgeOfLocationInformation>
    </CSLocationInformation>
    </Sh-Data>
    """
    xml_data="""<?xml version="1.0" encoding="UTF-8"?><Sh-Data><CSLocationInformation><LocationNumber>hJdHWQM=</LocationNumber><ServiceAreaId>UvACbQrDuA==</ServiceAreaId><VLRNumber><Address>kZd3UpMA8Q==</Address></VLRNumber><MSCNumber><Address>kZd3UpMA8Q==</Address></MSCNumber><AgeOfLocationInformation>201</AgeOfLocationInformation></CSLocationInformation></Sh-Data>"""
    xml_dom=xml.dom.minidom.parseString(xml_data)
    loc_dump(xml_dom)


