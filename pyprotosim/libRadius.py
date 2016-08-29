#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# March 2014 - 
# Version 0.3.2, Last change on March 06, 2014
# This software is distributed under the terms of BSD license.    
##################################################################

# All functions needed to build/decode radius messages

import xml.dom.minidom as minidom
import struct
import codecs
import socket
import sys
import logging
import time
import platform
import string
import random

# hashlib does not exist in python 2.4
# so we use md5 instead
# but md5 is deprecated, so...
try:
    import hashlib
    md5_constructor = hashlib.md5
except ImportError:
    # For python 2.4
    import md5
    md5_constructor = md5.new

# Include common routines for all modules

ERROR = -1
    
# Hopefully let's keep dictionary definition compatibile
class AVPItem:
    def __init__(self):
        self.code=0
        self.name=""
        self.vendor=0
        self.type=""
        self.tag=""
        self.mandatory=""
        
class HDRItem:
    def __init__(self):
        self.Code=0
        self.Identifier=0
        self.len=0
        self.Authenticator=0
        self.msg=""

#----------------------------------------------------------------------
# Dictionary routines

# Load simplified dictionary from <file>
def LoadDictionary(file):
    global dict_avps
    global dict_vendors
    global dict_commands
    global asString
    global asUTF8
    global asU32
    global asI32
    global asU64
    global asI64
    global asF32
    global asF64
    global asIP
    global asTime
    global asU24
    global asTString
    global asTPasswd
    doc = minidom.parse(file)
    node = doc.documentElement
    dict_avps = doc.getElementsByTagName("avp")
    dict_vendors = doc.getElementsByTagName("vendor")
    dict_commands=doc.getElementsByTagName("command")
    # Now lets process typedefs
    asString=["OctetString"]
    asUTF8=["UTF8String"]
    asI32=["Integer32"]
    asU32=["Unsigned32"]
    asF32=["Float32"]
    asI64=["Integer64"]
    asU64=["Unsigned64"]
    asF64=["Float64"]
    asIP=["IPAddress"]
    asTime=["Time"] 
    asU24=["Unsigned24"]
    asTString=["TaggedString"]
    asTPasswd=["TaggedPassword"]
    dict_typedefs=doc.getElementsByTagName("typedef")
    for td in dict_typedefs:
        tName=td.getAttribute("name")
        tType=td.getAttribute("type")
        if tType in asString:
           asString.append(tName)
        if tType in asUTF8:
           asUTF8.append(tName)
        if tType in asU32:
           asU32.append(tName)
        if tType in asI32:
           asI32.append(tName)
        if tType in asI64:
           asI64.append(tName)    
        if tType in asU64:
           asU64.append(tName)           
        if tType in asF32:
           asF32.append(tName)           
        if tType in asF64:
           asF64.append(tName)           
        if tType in asIP:
           asIP.append(tName)
        if tType in asTime:
           asTime.append(tName) 
        if tType in asU24:
           asU24.append(tName)
        if tType in asTString:
           asTString.append(tName)
        if tType in asTPasswd:
           asTPasswd.append(tName)
        
# Find AVP definition in dictionary: User-Name->1
def dictAVPname2code(A,avpname,avpvalue):
    dbg="Searching dictionary for N",avpname,"V",avpvalue
    logging.debug(dbg)
    for avp in dict_avps:
        A.name = avp.getAttribute("name")
        A.code = avp.getAttribute("code")
        A.mandatory=avp.getAttribute("mandatory")
        A.type = avp.getAttribute("type")
        A.tag = avp.getAttribute("tag")
        vId = avp.getAttribute("vendor-id")
        if avpname==A.name:
           if vId=="":
                A.vendor=0
           else:
                A.vendor=dictVENDORid2code(vId)
           return
    dbg="Searching dictionary failed for N",avpname,"V",avpvalue
    bailOut(dbg)

# Find AVP definition in dictionary: 1->User-Name
def dictAVPcode2name(A,avpcode,vendorcode):
    dbg="Searching dictionary for ","C",avpcode,"V",vendorcode
    logging.debug(dbg)
    A.vendor=dictVENDORcode2id(int(vendorcode))
    for avp in dict_avps:
        A.name = avp.getAttribute("name")
        A.type = avp.getAttribute("type")
        A.code = int(avp.getAttribute("code"))
        A.mandatory=avp.getAttribute("mandatory")
        A.tag = avp.getAttribute("tag")
        vId = avp.getAttribute("vendor-id")
        if int(avpcode)==A.code:
            if vId=="":
               vId="None"
            if vId==A.vendor:
               return 
    logging.info("Unsuccessful search")
    A.code=avpcode
    A.name="Unknown Attr-"+str(A.code)+" (Vendor:"+A.vendor+")"
    A.type="OctetString"
    return 

# Find Vendor definition in dictionary: 10415->TGPP
def dictVENDORcode2id(code):
    dbg="Searching Vendor dictionary for C",code
    logging.debug(dbg)
    for vendor in dict_vendors:
        vCode=vendor.getAttribute("code")
        vId=vendor.getAttribute("vendor-id")
        if code==int(vCode):
            return vId
    dbg="Searching Vendor dictionary failed for C",code
    bailOut(dbg)

# Find Vendor definition in dictionary: TGPP->10415
def dictVENDORid2code(vendor_id):
    dbg="Searching Vendor dictionary for V",vendor_id
    logging.debug(dbg)
    for vendor in dict_vendors:
        Code=vendor.getAttribute("code")
        vId=vendor.getAttribute("vendor-id")
        if vendor_id==vId:
            return int(Code)
    dbg="Searching Vendor dictionary failed for V",vendor_id
    bailOut(dbg)

# Find Command definition in dictionary: Access-Request->1
def dictCOMMANDname2code(name):
    for command in dict_commands:
         cName=command.getAttribute("name")
         cCode=command.getAttribute("code")
         if cName==name:
            return int(cCode)
    dbg="Searching CMD dictionary failed for N",name
    bailOut(dbg)

# Find Command definition in dictionary: 1->Access-Request    
def dictCOMMANDcode2name(code):
    cmd=ERROR
    for command in dict_commands:
         cName=command.getAttribute("name")
         cCode=command.getAttribute("code")
         if code==int(cCode):
            cmd=cName
    return cmd

#----------------------------------------------------------------------
# These are defined on Unix python.socket, but not on Windows
# Pack/Unpack IP address
def inet_pton(address_family, ip_string): 
    #Convert an IP address from text represenation to binary form
    if address_family == socket.AF_INET:
        return socket.inet_aton(ip_string)
    elif address_family == socket.AF_INET6:
        # IPv6: The use of "::" indicates one or more groups of 16 bits of zeros.
        # We deal with this form of wildcard using a special marker. 
        JOKER = "*"
        while "::" in ip_string:
            ip_string = ip_string.replace("::", ":" + JOKER + ":")
        joker_pos = None
        # The last part of an IPv6 address can be an IPv4 address
        ipv4_addr = None
        if "." in ip_string:
            ipv4_addr = ip_string.split(":")[-1]
        result = ""
        parts = ip_string.split(":")
        for part in parts:
            if part == JOKER:
                # Wildcard is only allowed once
                if joker_pos is None:
                   joker_pos = len(result)
                else:
                   bailOut("Illegal syntax for IP address")
            elif part == ipv4_addr:
                # FIXME: Make sure IPv4 can only be last part
                # FIXME: inet_aton allows IPv4 addresses with less than 4 octets 
                result += socket.inet_aton(ipv4_addr)
            else:
                # Each part must be 16bit. Add missing zeroes before decoding. 
                try:
                    result += part.rjust(4, "0").decode("hex")
                except TypeError:
                    bailOut("Illegal syntax for IP address")
        # If there's a wildcard, fill up with zeros to reach 128bit (16 bytes) 
        if JOKER in ip_string:
            result = (result[:joker_pos] + "\x00" * (16 - len(result))
                      + result[joker_pos:])
        if len(result) != 16:
            bailOut("Illegal syntax for IP address")
        return result
    else:
        bailOut("Address family not supported")

def inet_ntop(address_family, packed_ip): 
    #Convert an IP address from binary form into text represenation
    if address_family == socket.AF_INET:
        return socket.inet_ntoa(packed_ip)
    elif address_family == socket.AF_INET6:
        # IPv6 addresses have 128bits (16 bytes)
        if len(packed_ip) != 16:
            bailOut("Illegal syntax for IP address")
        parts = []
        for left in [0, 2, 4, 6, 8, 10, 12, 14]:
            try:
                value = struct.unpack("!H", packed_ip[left:left+2])[0]
                hexstr = hex(value)[2:]
            except TypeError:
                bailOut("Illegal syntax for IP address")
            parts.append(hexstr.lstrip("0").lower())
        result = ":".join(parts)
        while ":::" in result:
            result = result.replace(":::", "::")
        # Leaving out leading and trailing zeros is only allowed with ::
        if result.endswith(":") and not result.endswith("::"):
            result = result + "0"
        if result.startswith(":") and not result.startswith("::"):
            result = "0" + result
        return result
    else:
        bailOut("Address family not supported yet")

#Pack IP address  
def pack_address(address):
    # This has issue on Windows platform
    # addrs=socket.getaddrinfo(address, None)
    # This is NOT a proper code, but it will do for now
    # unfortunately, getaddrinfo does not work on windows with IPv6
    if address.find('.')!=ERROR:
        raw = inet_pton(socket.AF_INET,address);
        d=struct.pack('!h4s',1,raw)
        return d[2:]
    if address.find(':')!=ERROR:
        raw = inet_pton(socket.AF_INET6,address);
        d=struct.pack('!h16s',2,raw)
        return d
    dbg='Malformed IP'
    bailOut(dbg)

#----------------------------------------------------------------------
# Decoding section
#

def decode_Integer32(data):
    ret=struct.unpack("!I",data.decode("hex"))[0]
    return int(ret)

def decode_Integer64(data):
    ret=struct.unpack("!Q",data.decode("hex"))[0]
    return int(ret)
  
def decode_Unsigned32(data):
    ret=struct.unpack("!I",data.decode("hex"))[0]
    return int(ret)
  
def decode_Unsigned64(data):
    ret=struct.unpack("!Q",data.decode("hex"))[0]
    return int(ret)

def decode_Float32(data):
    ret=struct.unpack("!f",data.decode("hex"))[0]
    return ret

def decode_Float64(data):
    ret=struct.unpack("!d",data.decode("hex"))[0]
    return ret
    
def decode_Address(data):
    if len(data)<=16:
        ret=inet_ntop(socket.AF_INET,data.decode("hex"))
    else:
        ret=inet_ntop(socket.AF_INET6,data[4:].decode("hex"))
    return ret

def decode_OctetString(data,dlen):
    fs="!"+str(dlen-2)+"s"
    dbg="Decoding String with format:",fs
    logging.debug(dbg)
    ret=struct.unpack(fs,data.decode("hex")[0:dlen-2])[0]
    return ret

def decode_UTF8String(data,dlen):
    fs="!"+str(dlen-8)+"s"
    dbg="Decoding UTF8 format:",fs
    logging.debug(dbg)
    ret=struct.unpack(fs,data.decode("hex")[0:dlen-8])[0]
    utf8=utf8decoder(ret)
    return utf8[0]

def decode_Unsigned24(data):
    (tag,data)=chop_msg(data,2)
    print data,len(data)
    while len(data)<8:
        data="0"+data
    ret=struct.unpack("!I",data.decode("hex"))[0]
    return (ord(tag.decode("hex")),int(ret))
    
def decode_TString(data,dlen):
    (tag,data)=chop_msg(data,2)
    return (ord(tag.decode("hex")),decode_OctetString(data,dlen-2))

def decode_TPasswd(data,dlen):
    print data,dlen,len(data)
    (tag,data)=chop_msg(data,2)
    (salt,data)=chop_msg(data,4)
    return (ord(tag.decode("hex")),salt,decode_OctetString(data,dlen-6))
    
#----------------------------------------------------------------------
    
# Quit program with error
def bailOut(msg):
    logging.error(msg)
    sys.exit(1)
    
#Split message into parts (remove field from remaining body)
def chop_msg(msg,size):
    return (msg[0:size],msg[size:])
    
#----------------------------------------------------------------------

#    0                   1                   2
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#   |     Type      |    Length     |  Value ...
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

#    0                   1                   2
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#   |     Type      |    Length     |  CHAP Ident   |  String ...
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#    0                   1                   2                   3

#   Vendor-Specific
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |     Type      |  Length       |            Vendor-Id
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        Vendor-Id (cont)           | Vendor type   | Vendor length |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |    Attribute-Specific...
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

# Tunnel-Type
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |     Type      |    Length     |     Tag       |     Value
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#               Value (cont)        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |     Type      |    Length     |       Tag     |    String ...
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#   Tunnel-Type Password
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |     Type      |    Length     |     Tag       |   Salt
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      Salt (cont)  |   String ...
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# Common finishing touch for all types
def encode_finish(A,pktlen,data):
    ret=data
    dbg="Packing","C:",A.code,"V:",A.vendor,"L:",pktlen,"D:",ret
    logging.debug(dbg)
    ret=("%02X"%int(A.code))+("%02X"%int(pktlen))+ret
    if A.vendor!=0:
        ret=("%02X"%26)+("%02X"%(6+len(ret)/2))+("%08X"%int(A.vendor))+ret
    return ret  

def encode_OctetString(A,data):
    fs="!"+str(len(data))+"s"
    dbg="Encoding String format:",fs
    logging.debug(dbg)
    ret=struct.pack(fs,data).encode("hex")
    pktlen=2+len(ret)/2
    return encode_finish(A,pktlen,ret)

def encode_UTF8String(A,data):
    utf8data=utf8encoder(data)[0]
    fs="!"+str(len(utf8data))+"s"
    dbg="Encoding UTF8",utf8data,"L",len(utf8data),"F",fs
    logging.debug(dbg)
    ret=struct.pack(fs,utf8data).encode("hex")
    pktlen=2+len(ret)/2
    return encode_finish(A,pktlen,ret)

def encode_Integer32(A,data):
    ret=struct.pack("!I",int(data)).encode("hex")
    pktlen=6
    return encode_finish(A,pktlen,ret)
    
def encode_Unsigned32(A,data):
    r=struct.pack("!I",int(data))
    ret=r.encode("hex")
    pktlen=6
    return encode_finish(A,pktlen,ret)

def encode_Float32(A,data):
    ret=struct.pack("!f",data).encode("hex")
    pktlen=6
    return encode_finish(A,pktlen,ret)

def encode_Integer64(A,data):
    ret=struct.pack("!Q",data).encode("hex")
    pktlen=8
    return encode_finish(A,pktlen,ret)

def encode_Unsigned64(A,data):
    ret=struct.pack("!Q",data).encode("hex")
    pktlen=8
    return encode_finish(A,pktlen,ret)

def encode_Float64(A,data):
    ret=struct.pack("!d",data).encode("hex")
    pktlen=10
    return encode_finish(A,pktlen,ret)
    
def encode_Address(A,data):
    ret=pack_address(data).encode("hex")
    pktlen=2+len(ret)/2
    return encode_finish(A,pktlen,ret)
    
def encode_Unsigned24(A,data):
    r=struct.pack("!I",int(data))
    ret=r.encode("hex")
    pktlen=6
    return encode_finish(A,pktlen,ret[2:])    

def encode_TString(A,data):
    fs="!"+str(len(data))+"s"
    dbg="Encoding String format:",fs
    logging.debug(dbg)
    ret=struct.pack(fs,data).encode("hex")
    pktlen=2+len(ret)/2
    return encode_finish(A,pktlen,ret)

def encode_TPasswd(A,data):
    fs="!"+str(len(data))+"s"
    dbg="Encoding String format:",fs
    logging.debug(dbg)
    ret=struct.pack(fs,data).encode("hex")
    pktlen=2+len(ret)/2
    return encode_finish(A,pktlen,ret)    
   
def do_encode(A,data):
    if A.type in asUTF8:
        return encode_UTF8String(A,data)
    if A.type in asI32:
        return encode_Integer32(A,data)
    if A.type in asU32:
        return encode_Unsigned32(A,data)
    if A.type in asI64:
        return encode_Integer64(A,data)
    if A.type in asU64:
        return encode_Unsigned64(A,data)
    if A.type in asF32:
        return encode_Float32(A,data)
    if A.type in asF64:
        return encode_Float64(A,data)
    if A.type in asIP:
        return encode_Address(A,data)
    if A.type in asTime:
        return encode_Time(A,data)
    if A.type in asU24:
        return encode_Unsigned24(A,data)        
    if A.type in asTString:
        return encode_TString(A,data)        
    if A.type in asTPasswd:
        return encode_TPasswd(A,data)        
    # default is OctetString  
    return encode_OctetString(A,data)  

# Find AVP Definition in dictionary and encode it
def getAVPDef(AVP_Name,AVP_Value):
    A=AVPItem()
    dictAVPname2code(A,AVP_Name,AVP_Value)
    if A.name=="":
       logging.error("AVP with that name not found")
       return ""
    if A.code==0:
       logging.error("AVP Code not found")
       return ""
    if A.type=="":
       logging.error("AVP type not defined")
       return ""
    if A.vendor<0:
       logging.error("Vendor ID does not match")
       return ""
    else:
        data=AVP_Value
    dbg="AVP dictionary def","N",A.name,"C",A.code,"M",A.mandatory,"T",A.type,"V",A.vendor,"D",data
    logging.debug(dbg)
    return do_encode(A,data) 

################################
# Main encoding routine     
def encodeAVP(AVP_Name,AVP_Value):
    dbg="Packing AVP",AVP_Name,AVP_Value
    logging.info(dbg)
    if type(AVP_Value).__name__=='list':
        p=''
        for x in AVP_Value:
            p=p+x
        msg=getAVPDef(AVP_Name,p.decode("hex"))
    else:
        msg=getAVPDef(AVP_Name,AVP_Value)
    dbg="Encoded as:",msg
    logging.info(dbg)
    return msg    

#----------------------------------------------------------------------
################################
# Main decoding routine  
# Input: single AVP as HEX string
def decodeAVP(msg):
    (scode,msg)=chop_msg(msg,2)
    (slen,msg)=chop_msg(msg,2)
    dbg="Decoding ","C",scode,"L",slen,"D",msg
    logging.debug(dbg)
    mcode=ord(scode.decode("hex"))
    mvid=0
    if scode.lower()=="1a":         # Vendor-Specific
        (svendor,msg)=chop_msg(msg,8)
        (scode,msg)=chop_msg(msg,2)
        (slen,msg)=chop_msg(msg,2)
        dbg="Decoding with vendor","C",scode,"L",slen,"D",msg
        logging.debug(dbg)
        mcode=ord(scode.decode("hex"))
        mvid=decode_Integer32(svendor)
    mlen=ord(slen.decode("hex"))
    A=AVPItem()
    dictAVPcode2name(A,mcode,mvid)
    dbg="Read","N",A.name,"T",A.type,"C",A.code,"L",slen,mlen,"V",A.vendor,mvid,"D",msg
    logging.debug(dbg)
    ret=""
    decoded=False
    if A.type in asI32:
        logging.debug("Decoding Integer32")
        ret= decode_Integer32(msg)
        decoded=True
    if A.type in asI64:
        decoded=True
        logging.debug("Decoding Integer64")
        ret= decode_Integer64(msg)
    if A.type in asU32:
        decoded=True
        logging.debug("Decoding Unsigned32")
        ret= decode_Unsigned32(msg)
    if A.type in asU64:
        decoded=True
        logging.debug("Decoding Unsigned64")
        ret= decode_Unsigned64(msg)
    if A.type in asF32:
        decoded=True
        logging.debug("Decoding Float32")
        ret= decode_Float32(msg)
    if A.type in asF64:
        decoded=True
        logging.debug("Decoding Float64")
        ret= decode_Float64(msg)        
    if A.type in asUTF8:
        decoded=True
        logging.debug("Decoding UTF8String")
        ret= decode_UTF8String(msg,mlen)
    if A.type in asIP:
        decoded=True
        logging.debug("Decoding IPAddress")
        ret= decode_Address(msg)
    if A.type in asTime:
        decoded=True
        logging.debug("Decoding Time")
        ret= decode_Time(msg)
    if A.type in asU24:
        decoded=True
        logging.debug("Decoding U24")
        ret= decode_Unsigned24(msg)
    if A.type in asTString:
        decoded=True
        logging.debug("Decoding TString")
        ret= decode_TString(msg,mlen)
    if A.type in asTPasswd:
        decoded=True
        logging.debug("Decoding TPasswd")
        ret= decode_TPasswd(msg,mlen)        
    if not decoded:
      # default is OctetString
      logging.debug("Decoding OctetString")
      ret= decode_OctetString(msg,mlen)
    dbg="Decoded as",A.name,ret
    logging.info(dbg)
    return (A.name,ret)

# Search for AVP in undecoded list
# Return value if exist, ERROR if not   
def findAVP(what,list):
    for avp in list:
        if isinstance(avp,tuple):
           (Name,Value)=avp
        else:
           (Name,Value)=decodeAVP(avp)
        if Name==what:
           return Value
    return ERROR
    
#---------------------------------------------------------------------- 
# Header and packet routines

#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |     Code      |  Identifier   |            Length             |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                                                               |
#   |                         Authenticator                         |
#   |                                                               |
#   |                                                               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  Attributes ...
#   +-+-+-+-+-+-+-+-+-+-+-+-+-

def joinAVPs(avps):
    data=""
    for avp in avps:
        data=data+avp
    return data

# Create radius packet    
def createPacket(H):
    # since all data is hex ecoded, divide by 2 and add header length
    H.len=len(H.msg)/2+20
    ret="%02X"%H.Code+"%02X"%int(H.Identifier) + "%04X"%int(H.len)
    ret=ret+H.Authenticator.encode("hex")+H.msg
    dbg="Header fields","C",H.Code,"I",H.Identifier,"L",H.len,"A",H.Authenticator
    logging.debug(dbg)
    dbg="Radius hdr+data",ret
    logging.debug(dbg)
    return ret

# Create message authenticator    
def createAuthenticator():
    ret=''
    for i in range(16):
        ret=ret+chr(random.randrange(0, 256))
    return ret

# For Accounting, initial authenticator is 16 zeroes 
def createZeroAuthenticator():
    ret=''
    for i in range(16):
        ret=ret+chr(0)
    return ret
    
# Create response authenticator
def calcAuthenticator(H,auth,secret):
    #ResponseAuth = MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
    mlen=len(H.msg)/2+20
    msg="%02X"%H.Code+"%02X"%int(H.Identifier) + "%04X"%int(mlen)
    msg=msg+auth.encode('hex')+H.msg+secret.encode("hex")
    m=md5_constructor(msg.decode("hex")).digest()
    return m
    
# Create radius Request from <avps> and fields from Header H  
def createReq(H,avps):
    H.msg=joinAVPs(avps)
    # Authenticator should be inserted when encoding password
    # So it is disabled here
    #H.Authenticator=createAuthenticator()
    ret=createPacket(H)
    return ret

# Create radius Packet from <avps> and fields from Header H + calculate Authenticator
# Use also as CreateRes
def createWithAuthenticator(H,auth,avps,secret):
    H.msg=joinAVPs(avps)
    H.Authenticator=calcAuthenticator(H,auth,secret)
    ret=createPacket(H)
    return ret 
    
#---------------------------------------------------------------------- 
# Main message decoding routine
# Input: radius message as HEX string    
# Result: class H with splitted message (header+message)
# AVPs in message are NOT splitted    
def stripHdr(H,msg):
    dbg="Incoming Radius msg",msg
    logging.debug(dbg)
    (scode,msg)=chop_msg(msg,2)
    (sid,msg)=chop_msg(msg,2)
    (slen,msg)=chop_msg(msg,4)
    (sauth,msg)=chop_msg(msg,32)
    dbg="Split hdr","C",scode,"I",sid,"L",slen,"A",sauth,"D",msg
    logging.debug(dbg)
    H.Code=ord(scode.decode("hex"))
    H.Identifier=ord(sid.decode("hex"))
    H.len=struct.unpack("!I","\00\00"+slen.decode("hex"))[0]
    H.Authenticator=sauth
    dbg="Read","C",H.Code,"I",H.Identifier,"L",H.len,"A",H.Authenticator
    logging.debug(dbg)
    dbg=dictCOMMANDcode2name(H.Code)
    logging.info(dbg)
    H.msg=msg
    return 
 
# Split AVPs from message
# Input: H.msg as hex string
# Result: list of undecoded AVPs 
def splitMsgAVPs(msg):
    ret=[]
    dbg="Incoming avps",msg
    logging.debug(dbg)
    while len(msg)<>0:
      slen="000000"+msg[2:4]
      plen=struct.unpack("!I",slen.decode("hex"))[0]
      (avp,msg)=chop_msg(msg,2*plen)
      dbg="Single AVP","L",plen,"D",avp
      logging.debug(dbg)
      ret.append(avp)
    return ret

#---------------------------------------------------------------------- 

# Decrypt radius password    
def PwDecrypt(password,authenticator,secret):
    buf = password
    pw = ''
    last = authenticator
    while buf:
        hash = md5_constructor(secret + last).digest()
        for i in range(16):
            pw += chr(ord(hash[i]) ^ ord(buf[i]))
        (last, buf) = (buf[:16], buf[16:])
    while pw.endswith(('\x00')):
        pw = pw[:-1]
    return pw.decode('utf-8')

# Encrypt radius password    
def PwCrypt(password,authenticator,secret):
    #Call the shared secret S and the pseudo-random 128-bit Request
    #Authenticator RA.  Break the password into 16-octet chunks p1, p2,
    #etc.  with the last one padded at the end with nulls to a 16-octet
    #boundary.  Call the ciphertext blocks c(1), c(2), etc.  We'll need
    #intermediate values b1, b2, etc.
    #    b1 = MD5(S + RA)       c(1) = p1 xor b1
    #    b2 = MD5(S + c(1))     c(2) = p2 xor b2
    #            .                       .
    #    bi = MD5(S + c(i-1))   c(i) = pi xor bi
    # The String will contain c(1)+c(2)+...+c(i) where + denotes concatenation.
    # On receipt, the process is reversed to yield the original password.  
    password = password.encode('utf-8')
    buf = password
    if len(password) % 16 != 0:
        buf += '\x00' * (16 - (len(password) % 16))
    hash = md5_constructor(secret + authenticator).digest()
    result = ''
    last = authenticator
    while buf:
        hash = md5_constructor(secret + last).digest()
        for i in range(16):
            result += chr(ord(hash[i]) ^ ord(buf[i]))
        last = result[-16:]
        buf = buf[16:]
    return result

# CHAP password    
def ChapPwCrypt(id,password,authenticator):
    #The RADIUS server looks up a password based on the User-Name,
    #encrypts the challenge using MD5 on the CHAP ID octet, that password,
    #and the CHAP challenge (from the CHAP-Challenge attribute if present,
    #otherwise from the Request Authenticator), and compares that result
    #to the CHAP-Password
    password = password.encode('utf-8')
    _pwd =  md5_constructor(chr(id)+password+authenticator).digest()
    for i in range(16):
        result += _pwd[i]
    return result    

# Password for Tunneled AVPs    
def TunnelPwCrypt(password,authenticator,salt,secret):
    #Call the shared secret S, the pseudo-random 128-bit Request
    #Authenticator (from the corresponding Access-Request packet) R,
    #and the contents of the Salt field A.  Break P into 16 octet
    #chunks p(1), p(2)...p(i), where i = len(P)/16.  
    #Intermediate values b(1), b(2)...c(i) are required.  Encryption
    #is performed in the following manner ('+' indicates concatenation):
    #   b(1) = MD5(S + R + A)    c(1) = p(1) xor b(1)
    #   b(2) = MD5(S + c(1))     c(2) = p(2) xor b(2)
    #        .                      .
    #   b(i) = MD5(S + c(i-1))   c(i) = p(i) xor b(i)
    #The resulting encrypted String field will contain
    #c(1)+c(2)+...+c(i).
    #On receipt, the process is reversed to yield the plaintext String.
    return PwCrypt(password,authenticator+salt,secret)

#---------------------------------------------------------------------- 
# DateTime routines

def getCurrentDateTime():
    t=time.localtime()
    return t.tm_year,t.tm_mon,t.tm_mday,t.tm_hour,t.tm_min,t.tm_sec

# converts to seconds since epoch
def epoch2date(sec):
    t=time.localtime(sec)
    return t.tm_year,t.tm_mon,t.tm_mday,t.tm_hour,t.tm_min,t.tm_sec

def date2epoch(tYear,tMon,tDate,tHr,tMin,tSec):  
    t=time.strptime("{0} {1} {2} {3} {4} {5}".format(tYear,tMon,tDate,tHr,tMin,tSec),"%Y %m %d %H %M %S")
    return time.mktime(t)

#----------------------------------------------------------------------  
# TS 29.060   
def encode_GeoLoc(LocType,MCC,MNC,LAC,CI):
    ret="%02X"%LocType
    if len(MNC)==2:
        ret=ret+MCC[1]+MCC[0]+'F'+MCC[2]+MNC[1]+MNC[0]
    else:
        ret=ret+MCC[1]+MCC[0]+MNC[2]+MCC[2]+MNC[1]+MNC[0]
    ret=ret+"%04X"%LAC
    if LocType==2:
        # RAC
        ret=ret+"%02X"%CI+"FF"
    else:
        # SAC,CI
        ret=ret+"%04X"%CI
    return ret
    
######################################################        
# History
# Ver 0.2.7 - May 25, 2012 - Radius Client - initial        
# Ver 0.3   - Oct 24, 2012 - Radius tunnel AVP support added
#           - Oct 30, 2012 - decoding vendor-specific attributes case mismatch fixed
#           - Oct 31, 2012 - converting time to/from epoch added
# Ver 0.3.1 - Nov 13, 2012 - bugfix in pack_addr (if IPv6 starts with ":")
#                          - encodeGeoLoc added
#                          - comments added
# Ver 0.3.2 - Mar 06, 2014 - Added ZeroAuthenticator for Radius accounting messages