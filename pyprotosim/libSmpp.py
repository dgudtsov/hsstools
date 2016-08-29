#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - Nov 2012
# Version 0.3.1, Last change on Nov 14, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# All functions needed to build/decode SMPP (Short Message Peer to Peer) messages

import xml.dom.minidom as minidom
import struct
import codecs
import socket
import sys
import logging
import time
import string

# Header fields

# Include common routines for all modules
ERROR = -1
 
# Hopefully let's keep dictionary definition compatibile
class AVPItem:
    def __init__(self):
        self.code=0
        self.name=""
        self.type=""
        
class HDRItem:
    def __init__(self):
        self.len=0
        self.operation=0
        self.result=0
        self.sequence=0
        self.msg=""
        self.mandatory=[]
        self.optional=[]
        
# Load simplified dictionary from <file>
def LoadDictionary(file):
    global dict_msg
    global dict_optional
    doc = minidom.parse(file)
    node = doc.documentElement
    dict_msg = doc.getElementsByTagName("msg")
    dict_optional = doc.getElementsByTagName("optional")

# Find Command definition in dictionary: 257->Capabilities-Exchange
def dictMSGcode2name(code):
    global dict_msg
    cmd=ERROR
    for cmd in dict_msg:
         cName=cmd.getAttribute("name")
         cCode=cmd.getAttribute("code")
         if code==cCode:
            return cName
    dbg="Unknown command",code
    bailOut(dbg)
    
def dictFindMandatoryAVP(code):
    global dict_msg
    ret=[]
    for command in dict_msg:
         cCode=command.getAttribute("code")
         if code==cCode:
            for cMandatory in command.getElementsByTagName("mandatory"):
                cName=cMandatory.getAttribute("name")
                ret.append(cName)
            return ret
    return ERROR

def dictFindOptionalAVPbyCode(code):
    for command in dict_optional:
         cCode=command.getAttribute("code")
         cName=command.getAttribute("name")
         if code==cCode:
            return cName
    return ERROR

def dictFindOptionalAVPbyName(name):
    for command in dict_optional:
         cCode=command.getAttribute("code")
         cName=command.getAttribute("name")
         if name==cName:
            return cCode
    return ERROR
    
def dictFindDetails(code,mName):
    global dict_msg
    for command in dict_msg:
         cCode=command.getAttribute("code")
         if code==cCode:
            for cMandatory in command.getElementsByTagName("mandatory"):
                cName=cMandatory.getAttribute("name")
                cType=cMandatory.getAttribute("type")
                cMax=cMandatory.getAttribute("max")
                if cName==mName:
                    return cName,cType,cMax
    dbg="Unknown",mName,"for code",code
    bailOut(dbg) 
    
#----------------------------------------------------------------------
#
# Decoding section
#

def decode_Integer32(data):
    ret=struct.unpack("!I",data.decode("hex"))[0]
    return int(ret)
    
def decode_Int(data):
    return ord(data.decode("hex"))
    
def decode_Integer16(data):
    ret=struct.unpack("!H",data.decode("hex"))[0]
    return int(ret)    
    
def decode_as(msg,cType,cMax):
    if cType=="C-OS":
        (sValue,msg)=smart_chop(msg,cMax)
        return (sValue.decode('hex'),msg)
    if cType=="Byte":
        (sValue,msg)=chop_msg(msg,2)
        return (str(decode_Int(sValue)),msg)
    if cType=="Hex":
        (sValue,msg)=chop_msg(msg,2)
        return (sValue,msg)
    if cType=="Word":
        (sValue,msg)=chop_msg(msg,4)
        return (str(decode_Integer16(sValue)),msg)
    if cType=="OS":
        (sValue,msg)=chop_msg(msg,cMax)
        return (sValue,msg)    
    dbg="Unknown type",cType
    bailOut(dbg)

#----------------------------------------------------------------------
    
# Quit program with error
def bailOut(msg):
    logging.error(msg)
    sys.exit(1)
    
#Split message into parts (remove field from remaining body)
def chop_msg(msg,size):
    return (msg[0:size],msg[size:])
    
def smart_chop(msg,cMax):
    ret=''
    count=0
    while msg[:2]!='00':
        (cc,msg)=chop_msg(msg,2)
        ret=ret+cc
        count+=1
        if count==cMax:
            break
        if len(msg)==0:
            return (ret,msg)
    if count!=cMax:
        (cc,msg)=chop_msg(msg,2)
    return (ret,msg)
    
#---------------------------------------------------------------------- 
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                      Command length                           | 
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                      Command id                               | 
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                      Command status                           | 
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                      Sequence number                          | 
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  Message=first Mandatory, then Optional parameters.....

# Main message decoding routine
# Input: diameter message as HEX string    
# Result: class H with splitted message (header+message)
# AVPs in message are NOT splitted
def stripHdr(H,msg):
    dbg="Incoming SMPP msg",msg
    logging.info(dbg)
    if len(msg)==0:
        return ERROR
    (slen,msg)=chop_msg(msg,8)
    (soperation,msg)=chop_msg(msg,8)
    (sresult,msg)=chop_msg(msg,8)
    (ssequence,msg)=chop_msg(msg,8)
    dbg="Split hdr","L",slen,"I",soperation,"S",sresult,"N",ssequence,"D",msg
    logging.debug(dbg)
    H.len=decode_Integer32(slen)
    H.operation=soperation
    H.result=decode_Integer32(sresult)
    H.sequence=decode_Integer32(ssequence)
    dbg=dictMSGcode2name(soperation)
    logging.info(dbg)
    H.msg=msg
    return 

# Split AVPs from message
# Input: H.msg as hex string
# Result: list of undecoded AVPs
def splitMsgAVPs(H):
    ret=[]
    dbg="Undecoded msg",H.msg
    opt=decodeMandatory(H)
    decodeOptional(H,opt)
    dbg="Mandatory:",H.mandatory
    logging.info(dbg)
    dbg="Optional:",H.optional
    logging.info(dbg)
    return

def decodeMandatory(H):
    msg=H.msg
    ret=[]
    for mandatory in dictFindMandatoryAVP(H.operation):
        cName,cType,cMax=dictFindDetails(H.operation,mandatory)
        dbg="mandatory param:",cName,cType,cMax
        logging.debug(dbg)
        # Fix to get previously defined length 
        #e.g short_message and short_message_len
        if cMax!='':
            if not cMax.isnumeric():
                for r in ret:
                    if string.find(r,cMax+'=')==0:
                        cMax=int(r[len(cMax)+1:])
        (data,msg)=decode_as(msg,cType,cMax)
        ret.append(cName+'='+data)
    H.mandatory=ret
    return msg

#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |              Tag              |             Length            | 
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |             Value             |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
    
def decodeOptional(H,msg):
    ret=[]
    while msg!='':
        (sTag,msg)=chop_msg(msg,4)
        (sLen,msg)=chop_msg(msg,4)
        vLen=decode_Integer16(sLen)
        (sValue,msg)=chop_msg(msg,2*vLen)
        cName=dictFindOptionalAVPbyCode(sTag)
#---------------------------------------------------------------------- 

def packHdr(H):
    # first add all avps into single string if needed
    if H.msg=="":
        H.msg=encodeMandatory(H)+encodeOptional(H)
    # since all data is hex ecoded, divide by 2 and add header length
    H.len=len(H.msg)/2+16
    ret="%08X" % H.len+H.operation + "%08X"%int(H.result)+"%08X"%int(H.sequence)
    ret=ret+H.msg
    dbg="Header fields","L",H.len,"O",H.operation,"R",H.result,"S",H.sequence,"M",H.msg
    logging.debug(dbg)
    dbg="SMPP hdr+data",ret
    logging.info(dbg)
    return ret
    
def encodeMandatory(H):    
    msg=''
    for mandatory in dictFindMandatoryAVP(H.operation):
        cName,cType,cMax=dictFindDetails(H.operation,mandatory)
        dbg="mandatory param:",cName,cType,cMax
        logging.debug(dbg)
        for v in H.mandatory:
            if string.find(v,cName+'=')==0:
                msg+=encodeAVP(cType,v[len(cName)+1:])
    dbg="Encoded mandatory:",msg
    logging.info(dbg)
    return msg

def encodeOptional(H):    
    msg=''
    return msg
    
def encodeAVP(cType,value):
    if cType=="C-OS":
        return value.encode("hex")+"00"
    if cType=="Byte":
        return "%02X"%int(value)
    if cType=="Word":
        return "%04X"%int(value)
    if cType=="OS":
        return value
    dbg="Unknown type",cType
    bailOut(dbg)    
#---------------------------------------------------------------------- 
 
# Connect to host:port (TCP) 
def Connect(host,port):
    # Create a socket (SOCK_STREAM means a TCP socket)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock
        
######################################################        
# History
# Ver 0.3.1 - Nov 16, 2012 - initial version
