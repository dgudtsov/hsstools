#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - March 2012
# Version 0.3, Last change on Oct 24, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# Decode diameter packet into individual AVPs

from libDiameter import *
import sys

if __name__ == "__main__":
    # level for decoding are: DEBUG, INFO, WARNING, ERROR, CRITICAL
    #logging.basicConfig(level=logging.DEBUG)
    LoadDictionary("dictDiameter.xml")
    msg=sys.argv[1]
    print "="*30
    H=HDRItem()
    stripHdr(H,msg)
    avps=splitMsgAVPs(H.msg)
    cmd=dictCOMMANDcode2name(H.flags,H.cmd)
    if cmd==ERROR:
        print 'Unknown command',H.cmd
    else:
        print cmd
    print "Hop-by-Hop=",H.HopByHop,"End-to-End=",H.EndToEnd,"ApplicationId=",H.appId
    for avp in avps:
      print "RAW AVP",avp
      print "Decoded AVP",decodeAVP(avp)
    print "-"*30    
