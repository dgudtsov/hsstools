#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.3.1, Last change on Nov 15, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# Decode SMPP packet 

from libSmpp import *
import sys

if __name__ == "__main__":
    # level for decoding are: DEBUG, INFO, WARNING, ERROR, CRITICAL
    logging.basicConfig(level=logging.DEBUG)
    LoadDictionary("dictSMPP.xml")
    msg=sys.argv[1]
    print msg
    print "="*30
    H=HDRItem()
    stripHdr(H,msg)

    print "Len=",H.len,"Code=",H.operation,"Status=",H.result,"Sequence=",H.sequence,"Message=",H.msg
    splitMsgAVPs(H)
    print "Mandatory:",H.mandatory
    print "Optional:",H.optional
    
######################################################
# History
# 0.3.1 - Nov 15, 2012 - SMPP decode initial version