#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - March 2012
# Version 0.2.5, Last change on Mar 16, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# Decode radius packet into individual AVPs

from libDhcp import *
import sys

if __name__ == "__main__":
    # level for decoding are: DEBUG, INFO, WARNING, ERROR, CRITICAL
    logging.basicConfig(level=logging.DEBUG)
    LoadDictionary("dictDHCP.xml")
    msg=sys.argv[1]
    print "="*30
    H=HDRItem()
    stripHdr(H,msg)
    print H.msg
    avps=splitMsgAVPs(H.msg)
    print avps
    cmd=dictCOMMANDcode2name(H.op)
    if cmd==ERROR:
        print 'Unknown command',H.op
    else:
        print cmd
    print "HW address type=",H.htype
    print "HW address len=",H.hlen
    print "Hops=",H.hops
    print "Transaction ID=",H.xid
    print "Elapsed seconds=",H.secs
    print "Flags=",H.flags
    print "Client IP",H.ciaddr
    print "My IP",H.MyIP
    print "Bootstrap server IP",H.ServerIP
    print "Relay IP=",H.RelayIP
    print "MAC=",H.MAC
    print "Server Host Name=",H.Host
    print "Optional parameters",H.Boot
    for avp in avps:
      print "RAW AVP",avp
      print "Decoded AVP",decodeAVP(avp)
    print "-"*30    
