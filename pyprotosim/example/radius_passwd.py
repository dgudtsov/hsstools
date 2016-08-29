#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.3, Last change on Oct 24, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# Encode/Decode radius password 

from libRadius import *
import sys

def create_Request(user,password,secret):
    # Create message header (empty)
    REQ=HDRItem()
    # Set command code
    REQ.Code=dictCOMMANDname2code("Access-Request")
    REQ.Identifier=1
    REQ.Authenticator=createAuthenticator()
    # Let's build Request with minimal fields for demonstration only
    REQ_avps=[]
    REQ_avps.append(encodeAVP("User-Name", user))
    REQ_avps.append(encodeAVP("User-Password", PwCrypt(password,REQ.Authenticator,secret)))
    # Add AVPs to header and calculate remaining fields
    msg=createReq(REQ,REQ_avps)
    # msg now contains Access-Request as hex string
    return msg
    
if __name__ == "__main__":
    # level for decoding are: DEBUG, INFO, WARNING, ERROR, CRITICAL
    #logging.basicConfig(level=logging.DEBUG)
    LoadDictionary("dictRadius.xml")
    USER="testuser"
    PASSWORD="password"
    SECRET="secret"
    msg=create_Request(USER,PASSWORD,SECRET)
    print msg
    print "="*30
    H=HDRItem()
    stripHdr(H,msg)
    avps=splitMsgAVPs(H.msg)
    for avp in avps:
        print decodeAVP(avp)
    enc_passwd=findAVP("User-Password",avps)
    print "Decrypted:",PwDecrypt(enc_passwd,H.Authenticator.decode("hex"),SECRET)

######################################################        
# History
# 0.3 - Oct 24, 2012 - Radius password encode/decode initial version    