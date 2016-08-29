#!/usr/bin/env python
##################################################################
# Copyright (c) 2012-2014, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 -
# Version 0.3.2, Last change on Mar 01, 2014
# This software is distributed under the terms of BSD license.    
##################################################################

# All functions needed to build/decode EAP Payload

import xml.dom.minidom as minidom
import struct
import sys
import logging
import time
import platform

# subprocess does not work as expected in python 2.4
# so we use commands instead
# but for Windows commands does not work, so...
import subprocess
import commands

ERROR=-1

# EAP-Payload specific definitions

EAP_CODE_REQUEST  = 1
EAP_CODE_RESPONSE = 2
EAP_CODE_SUCCESS  = 3
EAP_CODE_FAILURE  = 4

# EAP Method Types as allocated by IANA:
# http://www.iana.org/assignments/eap-numbers
# Only supported types are listed here
EAP_TYPE_IDENTITY = 1
EAP_TYPE_SIM      = 18
EAP_TYPE_AKA      = 23
EAP_TYPE_AKAPRIME = 50

class EAPItem:
    def __init__(self):
        self.cmd=0
        self.id=0
        self.len=0
        self.type=0
        self.stype=0
        self.msg=""
        self.avps=[]

#----------------------------------------------------------------------


# Quit program with error
def e_bailOut(msg):
    logging.error(msg)
    sys.exit(1)
    
#Split message into parts (remove field from remaining body)
def e_chop_msg(msg,size):
    return (msg[0:size],msg[size:])

def decodeU32(data):
    ret=struct.unpack("!I",data.decode("hex"))[0]
    return int(ret)

#----------------------------------------------------------------------    
# Load diameter dictionary
def LoadEAPDictionary(file):
    global dict_eaps
    global dict_eapsubs
    doc = minidom.parse(file)
    node = doc.documentElement
    dict_eaps=doc.getElementsByTagName("eap")
    dict_eapsubs=doc.getElementsByTagName("eapsub")
           
def dictEAPname2code(name):
    dbg="Searching EAP dictionary for N",name
    logging.debug(dbg)
    for eap in dict_eaps:
        Name=eap.getAttribute("name")
        Code=eap.getAttribute("code")
        Reserved=eap.getAttribute("reserved")
        if name==Name:
            return (int(Code),Reserved)
    dbg="Searching EAP dictionary failed for N",name
    e_bailOut(dbg)

def dictEAPcode2name(code):
    dbg="Searching EAP dictionary for C",code
    logging.debug(dbg)
    for eap in dict_eaps:
        Name=eap.getAttribute("name")
        Code=eap.getAttribute("code")
        Reserved=eap.getAttribute("reserved")
        if code==int(Code):
            return (Name,Reserved)
    dbg="Searching EAP dictionary failed for C",code
    e_bailOut(dbg)

#Not used here, but in tool_Payload_decode.py
def dictEAPSUBtype2name(stype):
    dbg="Searching EAP dictionary for S",stype
    logging.debug(dbg)
    for eap in dict_eapsubs:
        Name=eap.getAttribute("name")
        Stype=eap.getAttribute("subtype")
        if Stype=="":
            Stype=str(ERROR)
        if stype==int(Stype):
            return Name
    dbg="Searching EAP dictionary failed for S",stype
    e_bailOut(dbg)

#Not used here, but in client/example
def dictEAPSUBname2type(name):
    dbg="Searching EAP dictionary for N",name
    logging.debug(dbg)
    for eap in dict_eapsubs:
        Name=eap.getAttribute("name")
        Stype=eap.getAttribute("subtype")
        if name==Name:
            return int(Stype)
    dbg="Searching EAP dictionary failed for N",name
    e_bailOut(dbg)

#   EAP Packet format
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |     Code      |  Identifier   |            Length             |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |    Data ...
#   +-+-+-+-+

#   AT_SELECTED_VERSION - decode as value (Reserved field is value)
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    | AT_SELECTED...| Length = 1    |    Selected Version           |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#   AT_NONCE_MT - decode as reserved (reserved field is not used)
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |AT_NONCE_MT    | Length = 5    |           Reserved            |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    .                           NONCE_MT                            .
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#   AT_IDENTITY - decode as bytelen (Reserved field is len in bytes). 
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    | AT_IDENTITY   | Length        | Actual Identity Length        |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    .                       Identity (optional)                     .
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#   AT_PADDING - decode as include (Include reserved field)
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |  AT_PADDING   | Length        | Padding...                    |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
#    .                                                               .
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#   AT_RES - decode as bitlen (RES Length is in bit length)
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |     AT_RES    |    Length     |          RES Length           |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
#   .                             RES                               .
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   
def getEAPTypeName(type):
    if type==EAP_TYPE_IDENTITY:
       return ("Identity",0)
    if type==EAP_TYPE_SIM:
       return ("EAP-SIM",0)
    if type==EAP_TYPE_AKA:
        return ("EAP-AKA",0)
    if type==EAP_TYPE_AKAPRIME:
        return ("EAP-AKA'",0)
    return ("ERROR",ERROR)

def getEAPCodeName(code):
    if code==EAP_CODE_REQUEST:
        return "EAP-Request"
    if code==EAP_CODE_RESPONSE:
        return "EAP-Response"
    if code==EAP_CODE_SUCCESS:
        return "EAP-Success"
    if code==EAP_CODE_FAILURE:
        return "EAP-Failure"
    return "ERROR"

#   EAP-AKA(SIM) Header   
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |     Code      |  Identifier   |            Length             |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |     Type      |    Subtype    |           Reserved            |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# EAP AVPs can't be left as raw due to different packing methods
# So they MUST be packed as AVP tuples
def decode_EAP(msg):
    EAP=EAPItem()
    (scode,msg)=e_chop_msg(msg,2)
    EAP.code=ord(scode.decode("hex"))
    (sid,msg)=e_chop_msg(msg,2)
    EAP.id=ord(sid.decode("hex"))
    (slen,msg)=e_chop_msg(msg,4)
    EAP.len=decodeU32("0000"+slen)
    dbg="Decoding EAP-Payload","C",EAP.code,"I",EAP.id,"L",EAP.len
    logging.debug(dbg)
    #Failure does not have type, so stop here
    if EAP.code==EAP_CODE_FAILURE:
        return EAP
    if EAP.code==EAP_CODE_SUCCESS:
        return EAP
    (stype,msg)=e_chop_msg(msg,2)
    EAP.type=ord(stype.decode("hex"))
    (et,er)=getEAPTypeName(EAP.type)
    dbg="Debugging EAP-Payload","T",EAP.type,et,er
    logging.debug(dbg)
    #Identity has no other AVPs inside
    if EAP.type==EAP_TYPE_IDENTITY:
        EAP.avps.append(("Identity",msg.decode("hex")))
        return EAP
    if er!=ERROR:
        (ssub,msg)=e_chop_msg(msg,2)
        (sres,msg)=e_chop_msg(msg,4)
        EAP.stype=decodeU32("000000"+ssub)
    EAP.msg=msg
    EAP.avps=splitEAPAVPs(msg)
    return EAP

def encode_EAP(E):
    # since all data is hex ecoded, divide by 2 and add header length
    if int(E.cmd)==EAP_CODE_FAILURE:
        E.len=4
        ret="%02X" % E.cmd+"%02X"%E.id+"%04X"%E.len
        dbg="EAP-Payload",ret
        logging.debug(dbg)
        return ret
    if int(E.cmd)==EAP_CODE_SUCCESS:
        E.len=4
        ret="%02X" % E.cmd+"%02X"%E.id+"%04X"%E.len
        dbg="EAP-Payload",ret
        logging.debug(dbg)
        return ret
    if E.type==EAP_TYPE_IDENTITY:
        E.len=4+len(E.msg)/2
        ret="%02X" % E.cmd+"%02X"%E.id+"%04X"%E.len
        ret=ret+E.msg
        dbg="EAP-Payload",ret
        logging.debug(dbg)
        return ret
    E.msg=joinEAPAVP(E.avps)
    # Update len to new value
    E.len=len(E.msg)/2+8
    ret1="%02X" % E.cmd +"%02X"%E.id   +"%04X"%E.len
    ret2="%02X" % E.type+"%02X"%E.stype+"0000"
    ret=ret1+ret2+E.msg
    dbg="EAP-Payload",ret
    logging.debug(dbg)
    return ret

def splitEAPAVPs(msg):
    avps=[]
    while len(msg)>0:
        (stype,msg)=e_chop_msg(msg,2) # Type
        (slen,msg)=e_chop_msg(msg,2)  # Len
        (mtype,resdef)=dictEAPcode2name(decodeU32("000000"+stype))
        mlen=ord(slen.decode("hex"))
        (reserved,msg)=e_chop_msg(msg,4) # Reserved
        (dmsg,msg)=e_chop_msg(msg,2*4*(mlen-1)) # Data
        check=0
        if resdef=="value":
            check+=1
            data=reserved
        if resdef=="reserved":
            check+=1
            data=dmsg        
        if resdef=="bitlen":
            check+=1
            reslen=decodeU32("0000"+reserved)/4
            data=dmsg[:reslen]
        if resdef=="bytelen":
            check+=1
            reslen=decodeU32("0000"+reserved)*2
            data=dmsg[:reslen]
        if resdef=="include":
            check+=1
            data=reserved+dmsg
        if check==0:
            # All undefined values are skipped 
            e_bailOut("Unsuccessful decoding EAP AVP")
        dbg="EAP AVP",mtype,"=",data,"+",resdef,"(",slen,")",len(data)/2,len(msg)/2
        logging.debug(dbg)
        avps.append((mtype,data))
    return avps

def addEAPIdentity(msg):
    return "%02X"%EAP_TYPE_IDENTITY+msg.encode("hex")

def addEAPAVP(name,value):
    (code,reserved)=dictEAPname2code(name)
    ret="%02X"%int(code)
    mlen=(len(value)+7)/8+1
    # Special case for AT_SELECTED_VERSION
    if int(code)==16:
        ret=ret+"01"
    else:
        ret=ret+"%02X"%mlen
    dbg="Adding EAP",code,reserved,name,value
    logging.debug(dbg)
    # FIXME - this part of code is not well tested.
    check=0
    if reserved=="bitlen":
        ret=ret+"%04X"%(len(value)*4)
        check+=1
    if reserved=="bytelen":
        ret=ret+"%04X"%(len(value)/2)
        check+=1
    if reserved=="include":
        # This might be wrong, but I don"t have any to test
        check+=1
    if reserved=="value":
        check+=1
    if check==0:
        # All default and undefined values are 0
        ret=ret+"0000"
    ret=ret+value
    # Fix padding
    while len(ret)/2<calc_padding(len(ret)/2):
        ret=ret+"00"
    dbg="EAP Encoded as",ret
    logging.debug(dbg)
    return ret

# Calculate message padding
def calc_padding(msg_len):
    return (msg_len+3)&~3
    
def joinEAPAVP(avps):
    ret=""
    for a in avps:
        (name,value)=a
        ret=ret+addEAPAVP(name,value)
    return ret

def exec_calc(cmd_type,params):
    args=cmd_type+" "+params
    #p=subprocess.Popen(["./eapcalc",args],stdout=subprocess.PIPE)
    #ret,err=p.communicate()
    dbg="Calc input",platform.system(),cmd_type,params
    logging.debug(dbg)    
    if platform.system()=="Windows":
        p=subprocess.Popen("eapcalc.exe"+" "+args,stdout=subprocess.PIPE)
        ret,err=p.communicate()
    if platform.system()=="SunOS":
        ret=commands.getoutput("./eapcalc.solx86"+" "+args)
    #>>> platform.linux_distribution()
    #('Mandriva Linux', '2010.0', 'Official')    
    # FIXME: Learn to make distinction based on libc6 (e.g REHL/Ubuntu) to trigger proper aplication
    if platform.system()=="Linux":
        ret=commands.getoutput("./eapcalc.linux"+" "+args)
    dbg="Calc output",ret
    logging.debug(dbg)
    if cmd_type=="milenage-f2345":
        #XRES,CK,IK,AK,AKS
        XRES=findValue(ret,"XRES=")
        CK=findValue(ret,"CK=")
        IK=findValue(ret,"IK=")
        AK=findValue(ret,"AK=")
        AKS=findValue(ret,"AKS=")
        return XRES,CK,IK,AK,AKS
    if cmd_type=="milenage-f1":
        #XMAC,MACS
        XMAC=findValue(ret,"XMAC=")
        MACS=findValue(ret,"MACS=")
        return XMAC,MACS
    if cmd_type=="mac-sim":
        #MAC
        MAC=findValue(ret,"MAC=")
        return MAC
    if cmd_type=="mac-aka":
        #MAC
        MAC=findValue(ret,"MAC=")
        return MAC
    if cmd_type=="mac-akaprime":
        #MAC
        MAC=findValue(ret,"MAC=")
        return MAC
    if cmd_type=="sim":
        #KENCR,KAUT,MSK,EMSK,MK
        MK=findValue(ret,"MK=")
        KENCR=findValue(ret,"KENCR=")
        KAUT=findValue(ret,"KAUT=")
        MSK=findValue(ret,"MSK=")
        EMSK=findValue(ret,"EMSK=")
        return KENCR,KAUT,MSK,EMSK,MK        
    if cmd_type=="aka":
        #KENCR,KAUT,MSK,EMSK,MK
        MK=findValue(ret,"MK=")
        KENCR=findValue(ret,"KENCR=")
        KAUT=findValue(ret,"KAUT=")
        MSK=findValue(ret,"MSK=")
        EMSK=findValue(ret,"EMSK=")
        return KENCR,KAUT,MSK,EMSK,MK
    if cmd_type=="akaprime":
        #KENCR,KAUT,MSK,EMSK,KRE
        KENCR=findValue(ret,"KENCR=")
        KAUT=findValue(ret,"KAUT=")
        KRE=findValue(ret,"KRE=")
        MSK=findValue(ret,"MSK=")
        EMSK=findValue(ret,"EMSK=")
        return KENCR,KAUT,MSK,EMSK,KRE
    if cmd_type=="encrypt":
        #ENCR_DATA
        DATA=findValue(ret,"ENCRYPTED=")
        return DATA
    if cmd_type=="decrypt":
        #RAW_DATA
        DATA=findValue(ret,"DECRYPTED=")
        return DATA

def findValue(res,start):
    for x in res.split("\n"):
        if x.startswith(start):
           dbg="Value",x,x[-1]
           logging.debug(dbg)
           # Fix for windows CR+LF instead of CR
           if x[-1]=="\r":
              x=x[:-1]
           ll=x.split("=")
           return ll[1]
    return ERROR

def addMAC(E,K,extra=""):
    E.avps.append(("AT_MAC","00"*16))
    tmp=encode_EAP(E)
    #Clear it so we can do it again
    E.msg=""
    # Call hmac1 or hmac256 based on E.type
    if E.type==EAP_TYPE_SIM:
        hmac_type="mac-sim"
    if E.type==EAP_TYPE_AKA:
        hmac_type="mac-aka"
    if E.type==EAP_TYPE_AKAPRIME:
        hmac_type="mac-akaprime"
    # Do the calc
    dbg="Calculate ",hmac_type,K,tmp
    logging.debug(dbg)
    params="0x"+K+" 0x"+tmp    
    if len(extra)>0:
        params+=" 0x"+extra
    MAC=exec_calc(hmac_type,params) 
    dbg="Output ",MAC
    logging.debug(dbg)
    # Replace empty with new MAC
    E.avps.pop()
    E.avps.append(("AT_MAC",MAC))
    tmp1=encode_EAP(E)
    return

def sim_calc_a3a8(RAND,K):
    logging.debug(dbg)
    SRES,KC=exec_calc("a3a8",params)
    return SRES,KC
    
def sim_calc_keys(Identity,KC,NONCE_MT,VERSION_LIST,SELECTED_VER):
    params=Identity+" 0x"+KC+" 0x"+NONCE_MT+" 0x"+VERSION_LIST+" "+SELECTED_VER
    dbg="Calculating SIM keys",params
    logging.debug(dbg)
    KENCR,KAUT,MSK,EMSK,MK=exec_calc("sim",params)
    return KENCR,KAUT,MSK,EMSK,MK
    
def aka_calc_milenage(OPc,K,RAND):
    params="0x"+OPc+" 0x"+K+" 0x"+RAND
    XRES,CK,IK,AK,AKS=exec_calc("milenage-f2345",params)
    return XRES,CK,IK,AK,AKS

def aka_calc_keys(Identity,Ck,Ik):
    params=Identity+" 0x"+Ck+" 0x"+Ik
    dbg="Calculating AKA keys",params
    logging.debug(dbg)
    KENCR,KAUT,MSK,EMSK,MK=exec_calc("aka",params)
    return KENCR,KAUT,MSK,EMSK,MK

def akap_calc_keys(Identity,Ck,Ik):
    params=Identity+" 0x"+Ck+" 0x"+Ik
    dbg="Calculating AKA' keys",params
    logging.debug(dbg)
    KENCR,KAUT,MSK,EMSK,KRE=exec_calc("akaprime",params)
    return KENCR,KAUT,MSK,EMSK,KRE

def decrypt_data(Iv,Kencr,encr_data):
    params="0x"+Iv+" 0x"+Kencr+" 0x"+encr_data
    DATA=exec_calc("decrypt",params)
    return DATA

def xor_string(s1, s2):
    # truncate the result to the minimum length
    trunc = min( len(s1), len(s2) )
    s1, s2 = s1[:trunc], s2[:trunc]
    res = ""
    # xor byte per byte
    for i in range(trunc):
        res += chr( ord(s1[i]) ^ ord(s2[i]) )
    return res

######################################################        
# History
# Ver 0.2.0 - Feb 17, 2012 - EAP-Payload decoder
# Ver 0.2.1 - Feb 19, 2012 - EAP-Payload+ AKA/AKA' C calculations
# Ver 0.2.8 - May 25, 2012 - EAP functions moved to separate source
#                          - bugfix: added padding on encoding, field size calculation checked