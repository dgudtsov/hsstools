#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.3.2, Last change on Mar 01, 2014
# This software is distributed under the terms of BSD license.    
##################################################################

# decoding EAP-Payload value into AVPs

import eap
import sys
import logging

if __name__ == "__main__":
    # level for decoding are: DEBUG, INFO, WARNING, ERROR, CRITICAL
    logging.basicConfig(level=logging.DEBUG)
    eap.LoadEAPDictionary("dictEAP.xml")
    msg=sys.argv[1]
    #msg="01020014120A00000F020002000100000D010000"
    print msg    
    E=eap.decode_EAP(msg)
    print "="*30
    print eap.getEAPCodeName(E.code)
    (et,er)=eap.getEAPTypeName(E.type)
    if er==0:
        print "Type:",et
    if E.stype!=0:
       x=eap.dictEAPSUBtype2name(E.stype)
       print "Subtype:",x
    for avp in E.avps:
       (code,data)=avp
       print code,"=",data
    print "-"*30

