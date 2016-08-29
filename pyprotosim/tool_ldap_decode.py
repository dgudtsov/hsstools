#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - November 2012
# Version 0.3.1, Last change on Nov 17, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# Decode LDAP packet

from libLdap import *
import sys
import socket

if __name__ == "__main__":
    msg=sys.argv[1]
    print "Input:",msg
    try:
        # Fire to test server for verification with wireshark
        # I use dummy-server.py
        HOST="192.168.89.129"
        PORT=8888
        # Connect to server
        Conn=Connect(HOST,PORT)
        # send data
        Conn.send(msg.decode("hex"))
        Conn.close()
    except:
        pass
    print "="*30
    msgId,appId,rest,unknown=decodeHDR(msg)
    L=decodeFinal(msgId,appId,rest,unknown) 
    # Just for the verbosity
    c,p,cmd=BERdecode(appId.decode("hex"))
    print "Application",appId,dictCmd2Name(dict_APP,cmd)
    # continue with decoding
    if cmd==0:
        print "messageId:",L.messageId
        print "code:",L.code
        print "version:",L.version
        print "name",L.name
        print "passwd",L.authentication
    if cmd==1:
        print "messageId:",L.messageId
        print "code:",L.code
        print "status", L.result, dictCmd2Name(dict_RES,L.result)
        print "matchedDN",L.matchedDN
        print "errorMSG",L.errorMSG
    if cmd==3:
        print "messageId:",L.messageId
        print "code:",L.code    
        print "baseObject",L.objectName
        print "scope",L.scope
        print "derefAliases", L.derefAliases
        print "sizeLimit",L.sizeLimit
        print "timeLImit",L.timeLimit
        print "typesOnly",L.typesOnly
        print "filter",L.filter
    if cmd==4:
        print "messageId:",L.messageId
        print "code:",L.code    
        print "objectName",L.objectName
        print "attributes",L.attributes   
    if cmd in [5,7,9,11]:
        print "messageId:",L.messageId
        print "code:",L.code
        print "status:",L.result, dictCmd2Name(dict_RES,L.result)
        print "matchedDN",L.matchedDN
        print "errorMSG",L.errorMSG       
    if cmd==6:
        print "messageId:",L.messageId
        print "code:",L.code
        print "objectName",L.objectName
        print "operation",L.operation
        print "modification",L.modification 
        print "controls",L.controls 
    if cmd==8:
        print "messageId:",L.messageId
        print "code:",L.code    
        print "objectName",L.objectName
        print "attributes",L.attributes     
    if cmd==10:
        print "messageId:",L.messageId
        print "code:",L.code    
        print "objectName",L.objectName
    
######################################################        
# History
# 0.2.9 - Oct 11, 2012 - initial version
# 0.3.1 - Nov 15, 2012 - add/delete/modify support
#       - Nov 17, 2012 - added "TCP resend" for wireshark verfication