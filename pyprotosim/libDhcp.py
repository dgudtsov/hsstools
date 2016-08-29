#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - Sep 2012
# Version 0.2.8, Last change on Sep 24, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# All functions needed to build/decode DHCP messages

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

# Include common routines for all modules

ERROR = -1

FLAG_BROADCAST = 0x8000
    
# Hopefully let's keep dictionary definition compatibile
class AVPItem:
    def __init__(self):
        self.code=0
        self.name=""
        self.vendor=0
        self.type=""
        self.mandatory=""
        self.slen=0
        
class HDRItem:
    def __init__(self):
        self.op=0
        self.htype=1
        self.hlen=6
        self.hops=0
        self.xid="%08X"%0
        self.secs=4
        self.flags=0
        self.ciaddr="0.0.0.0"
        self.MyIP="0.0.0.0"
        self.ServerIP="0.0.0.0"
        self.RelayIP="0.0.0.0"
        self.MAC=""
        self.Host=""
        self.Boot=""
        self.Cookie="6382536335".decode("hex")
        self.msg=""

#----------------------------------------------------------------------

# Load dictionary
def LoadDictionary(file):
    global dict_avps
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
    doc = minidom.parse(file)
    node = doc.documentElement
    dict_avps = doc.getElementsByTagName("avp")
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
        
# Find AVP definition in dictionary
def dictAVPname2code(A,avpname,avpvalue):
    dbg="Searching dictionary for N",avpname,"V",avpvalue
    logging.debug(dbg)
    for avp in dict_avps:
        A.name = avp.getAttribute("name")
        A.code = avp.getAttribute("code")
        A.type = avp.getAttribute("type")
        A.slen = 0
        mlen=avp.getAttribute("len")
        if mlen!="":
            A.slen=int(mlen)
        if avpname==A.name:
           return
    dbg="Searching dictionary failed for N",avpname,"V",avpvalue
    bailOut(dbg)

# Find AVP definition in dictionary
def dictAVPcode2name(A,avpcode):
    dbg="Searching dictionary for ","C",avpcode
    logging.debug(dbg)
    A.vendor=0
    for avp in dict_avps:
        A.name = avp.getAttribute("name")
        A.type = avp.getAttribute("type")
        A.code = int(avp.getAttribute("code"))
        mlen = avp.getAttribute("len")
        if mlen!="":
            A.slen=int(mlen)
        if int(avpcode)==A.code:
            vId="None"
            return 
    logging.info("Unsuccessful search")
    A.code=avpcode
    A.name="Unknown Attr-"+str(A.code)+" (Vendor:"+A.vendor+")"
    A.type="OctetString"
    A.slen=0
    return 

def dictCOMMANDname2code(name):
    global dict_commands
    for command in dict_commands:
         cName=command.getAttribute("name")
         cCode=command.getAttribute("code")
         if cName==name:
            return int(cCode)
    dbg="Searching CMD dictionary failed for N",name
    bailOut(dbg)
    
def dictCOMMANDcode2name(code):
    global dict_commands
    cmd=ERROR
    for command in dict_commands:
         cName=command.getAttribute("name")
         cCode=command.getAttribute("code")
         if code==int(cCode):
            cmd=cName
    return cmd
    
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
#   |     Code      |    Length     |  Value ...
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

def encode_finish(A,pktlen,data):
    ret=data
    dbg="Packing","C:",A.code,"L:",pktlen,"D:",ret
    logging.debug(dbg)
    ret=("%02X"%int(A.code))+("%02X"%int(pktlen))+ret
    #if A.vendor!=0:
    #    ret=("%02X"%26)+("%02X"%(6+len(ret)/2))+("%08X"%int(A.vendor))+ret
    return ret  

def encode_OctetString(A,data):
    fs="!"+str(len(data))+"s"
    dbg="Encoding String format:",fs
    logging.debug(dbg)
    ret=struct.pack(fs,data).encode("hex")
    pktlen=len(ret)/2
    return encode_finish(A,pktlen,ret)

def encode_UTF8String(A,data):
    utf8data=utf8encoder(data)[0]
    fs="!"+str(len(utf8data))+"s"
    dbg="Encoding UTF8",utf8data,"L",len(utf8data),"F",fs
    logging.debug(dbg)
    ret=struct.pack(fs,utf8data).encode("hex")
    pktlen=len(ret)/2
    return encode_finish(A,pktlen,ret)

def encode_Integer32(A,data):
    ret=struct.pack("!I",int(data)).encode("hex")
    if A.slen!=0:
        ret=ret[-2*A.slen:]
        pktlen=A.slen
    else:
        pktlen=4
    return encode_finish(A,pktlen,ret)
    
def encode_Unsigned32(A,data):
    r=struct.pack("!I",int(data))
    ret=r.encode("hex")
    if A.slen!=0:
        ret=ret[-2*A.slen:]
        pktlen=A.slen
    else:
        pktlen=4
    return encode_finish(A,pktlen,ret)

def encode_Float32(A,data):
    ret=struct.pack("!f",data).encode("hex")
    if A.slen!=0:
        pktlen=A.slen
    else:
        pktlen=4
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
    pktlen=8
    return encode_finish(A,pktlen,ret)
    
def encode_Address(A,data):
    ret=pack_address(data).encode("hex")
    pktlen=len(ret)/2
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
    dbg="AVP dictionary def","N",A.name,"C",A.code,"L",A.slen,"T",A.type,"V",A.vendor,"D",data
    logging.debug(dbg)
    return do_encode(A,data) 
    
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

def decodeAVP(msg):
    (scode,msg)=chop_msg(msg,2)
    (slen,msg)=chop_msg(msg,2)
    dbg="Decoding ","C",scode,"L",slen,"D",msg
    logging.debug(dbg)
    mcode=ord(scode.decode("hex"))
    mlen=ord(slen.decode("hex"))
    A=AVPItem()
    dictAVPcode2name(A,mcode,0)
    dbg="Read","N",A.name,"T",A.type,"C",A.code,"L",slen,mlen,"V",A.vendor,"D",msg
    logging.debug(dbg)
    ret=""
    decoded=False
    if A.type in asI32:
        logging.debug("Decoding Integer32")
        while len(msg)<8:
		msg="00"+msg
        ret= decode_Integer32(msg)
        decoded=True
    if A.type in asI64:
        decoded=True
        logging.debug("Decoding Integer64")
        ret= decode_Integer64(msg)
    if A.type in asU32:
        decoded=True
        logging.debug("Decoding Unsigned32")
        while len(msg)<8:
		msg="00"+msg
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
    if A.type=="Grouped":
        decoded=True
        logging.debug("Decoding Grouped")
        ret= decode_Grouped(msg)
    if not decoded:
      # default is OctetString
      logging.debug("Decoding OctetString")
      ret= decode_OctetString(msg,mlen)
    dbg="Decoded as",A.name,ret
    logging.info(dbg)
    return (A.name,ret)

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

def joinAVPs(avps):
    data=""
    for avp in avps:
        #while len(avp)/2<calc_padding(len(avp)/2):
        #    avp=avp+"00"
        data=data+avp
    return data

def createTransactionID():
    ret=''
    for i in range(4444):
        ret=ret+chr(random.randrange(0, 256))
    return ret
    
def addTrailing(val,slen):
    while len(val)<slen:
        val=val+'00'
    return val
    
def stripTrailing(val):
    if len(val)>2:
        while val[:-2]=='00':
            val=val[:-2]
            if len(val)==0:
                return ''
    return val

#---------------------------------------------------------------------- 
    
def stripHdr(H,msg):
    dbg="Decoding DHCP msg",msg
    logging.debug(dbg)
    (op,msg)=chop_msg(msg,2)
    (htype,msg)=chop_msg(msg,2)
    (hlen,msg)=chop_msg(msg,2)
    (hops,msg)=chop_msg(msg,2)
    (xid,msg)=chop_msg(msg,8)
    (secs,msg)=chop_msg(msg,4)
    (flags,msg)=chop_msg(msg,4)
    (ciaddr,msg)=chop_msg(msg,8)
    (MyIP,msg)=chop_msg(msg,8)
    (ServerIP,msg)=chop_msg(msg,8)
    (RelayIP,msg)=chop_msg(msg,8)
    (MAC,msg)=chop_msg(msg,32)
    (Host,msg)=chop_msg(msg,128)
    (Boot,msg)=chop_msg(msg,256)
    (Cookie,msg)=chop_msg(msg,8)
    dbg="Split hdr","C",op,"S",ServerIP,"M",MAC,"T",xid,"D",msg
    logging.debug(dbg)
    H.op=ord(op.decode("hex"))
    H.htype=ord(htype.decode("hex"))
    H.hlen=ord(hlen.decode("hex"))
    H.hops=ord(hops.decode("hex"))
    H.xid=struct.unpack("!I",xid.decode("hex"))[0]
    H.secs=struct.unpack("!I","\00\00"+secs.decode("hex"))[0]
    H.flags=struct.unpack("!I","\00\00"+flags.decode("hex"))[0]
    H.ciaddr=decode_Address(ciaddr)
    H.MyIP=decode_Address(MyIP)
    H.ServerIP=decode_Address(ServerIP)
    H.RelayIP=decode_Address(RelayIP)
    H.MAC=MAC[0:12]
    H.Host=Host
    H.Boot=Boot
    H.Cookie=Cookie
    H.msg=msg
    return 
    
def splitMsgAVPs(msg):
    ret=[]
    dbg="Incoming avps",msg
    logging.debug(dbg)
    while len(msg)<>0:
        scode="000000"+msg[:2]
        pcode=struct.unpack("!I",scode.decode("hex"))[0]
        if pcode==255:	# END Option
            break
        if pcode!=0:	# PAD Option
	    slen="000000"+msg[2:4]
            plen=struct.unpack("!I",slen.decode("hex"))[0]
            (avp,msg)=chop_msg(msg,4+2*plen)
            dbg="Single AVP","C",pcode,"L",plen,"D",avp
            logging.debug(dbg)
            ret.append(avp)
    return ret

#---------------------------------------------------------------------- 


#
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
    if address.find('.')>0:
        raw = inet_pton(socket.AF_INET,address);
        d=struct.pack('!h4s',1,raw)
        return d[2:]
    if address.find(':')>0:
        raw = inet_pton(socket.AF_INET6,address);
        d=struct.pack('!h16s',2,raw)
        return d
    dbg='Malformed IP'
    bailOut(dbg)

#----------------------------------------------------------------------
#   0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
#   +---------------+---------------+---------------+---------------+
#   |                            xid (4)                            |
#   +-------------------------------+-------------------------------+
#   |           secs (2)            |           flags (2)           |
#   +-------------------------------+-------------------------------+
#   |                          ciaddr  (4)                          |
#   +---------------------------------------------------------------+
#   |                          yiaddr  (4)                          |
#   +---------------------------------------------------------------+
#   |                          siaddr  (4)                          |
#   +---------------------------------------------------------------+
#   |                          giaddr  (4)                          |
#   +---------------------------------------------------------------+
#   |                                                               |
#   |                          chaddr  (16)                         |
#   |                                                               |
#   |                                                               |
#   +---------------------------------------------------------------+
#   |                                                               |
#   |                          sname   (64)                         |
#   +---------------------------------------------------------------+
#   |                                                               |
#   |                          file    (128)                        |
#   +---------------------------------------------------------------+
#   |                                                               |
#   |                          options (variable)                   |
#   +---------------------------------------------------------------+

def createPacket(D):
    dbg="Packing","OP:",D.op,"MyIP",D.MyIP,"Server",D.ServerIP
    logging.debug(dbg)
    hdr1=("%02X"%int(D.op))+("%02X"%int(D.htype))+("%02X"%int(D.hlen))+("%02X"%D.hops)
    #hdr2=D.xid
    hdr3=("%04X"%int(D.secs))+("%04X"%int(D.flags))
    hdr4=pack_address(D.ciaddr).encode("hex")
    hdr5=pack_address(D.MyIP).encode("hex")
    hdr6=pack_address(D.ServerIP).encode("hex")
    hdr7=pack_address(D.RelayIP).encode("hex")
    hdr8=addTrailing(D.MAC,2*16)
    hdr9=addTrailing(D.Host.encode("hex"),2*64)
    hdr10=addTrailing(D.Boot.encode("hex"),2*128)   
    hdr11=addTrailing(D.Cookie.encode("hex"),8)
    msgEND='FF'
    ret=hdr1+D.xid+hdr3+hdr4+hdr5+hdr6+hdr7+hdr8+hdr9+hdr10+hdr11+D.msg+msgEND
    # Minimal packet len is 300 bytes
    if len(ret)<2*300:
    	return addTrailing(ret,2*300)
    else:	
    	return ret
    
