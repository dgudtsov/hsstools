#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.2.6 Last change at Mar 18, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

#Next two lines are to include parent directory for testing
import sys
sys.path.append("..")
# Remove them normally

# Testing handling basic AVP types
from libRadius import *
import time

if __name__ == '__main__':
    #logging.basicConfig(level=logging.DEBUG)
    logging.basicConfig(level=logging.INFO)
    LoadDictionary("../dictRadius.xml")
    # Int32
    AVP=encodeAVP("NAS-Port",1025)
    decodeAVP(AVP)
    # IP Address
    AVP=encodeAVP("NAS-IP-Address",'172.30.211.2')
    decodeAVP(AVP)
    # EncryptedPassword
    SECRET="secret"
    AUTHENTICATOR=createAuthenticator()
    enc_pwd=PwCrypt('teststr',AUTHENTICATOR,SECRET)
    AVP=encodeAVP("User-Password",enc_pwd)
    (avp_name,pwd)=decodeAVP(AVP)
    print PwDecrypt(pwd,AUTHENTICATOR,SECRET)
    # OctetString
    AVP=encodeAVP("User-Name",'testutf')
    decodeAVP(AVP)

