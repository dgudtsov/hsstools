#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.3, Last change on Oct 24, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# Decode radius packet into individual AVPs

from libRadius import *
import sys

if __name__ == "__main__":
    # level for decoding are: DEBUG, INFO, WARNING, ERROR, CRITICAL
    #logging.basicConfig(level=logging.DEBUG)
    LoadDictionary("dictRadius.xml")
    msg=sys.argv[1]
    print "="*30
    H=HDRItem()
    stripHdr(H,msg)
    avps=splitMsgAVPs(H.msg)
    print "Code=",H.Code,"Identifier=",H.Identifier,"Authenticator=",H.Authenticator
    print dictCOMMANDcode2name(H.Code)
    print "-"*30
    for avp in avps:
      print "RAW AVP",avp
      print "Decoded AVP",decodeAVP(avp)
    print "-"*30    

######################################################
# History
# 0.3 - Oct 24, 2012 - Radius decode initial version