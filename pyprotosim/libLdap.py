#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 -
# Version 0.3.1, Last change on Nov 15, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# All functions needed to build/decode LDAP messages

import struct
import socket
import sys

ERROR = -1

# Encoding structure: CLASS(bit 7,8)+PC(bit 5)+Tag (bit 0-4)

dict_class={'UNIVERSAL':0x00,
            'APPLICATION':0x40,
            'CONTEXT_SPECIFIC':0x80,
            'PRIVATE':0xC0}

dict_pc={'PRIMITIVE':0,
         'CONSTRUCTED':0x20}

dict_tag={'EOC':0,
          'BOOLEAN':1,
          'INTEGER':2,
          'BIT_STRING':3,
          'OCTET_STRING':4,
          'NULL':5,
          'OBJECT_IDENTIFIER':6,
          'OBJECT_DESCRIPTOR':7,
          'EXTERNAL':8,
          'FLOAT':9,
          'ENUMERATED':10,
          'EMBEDDED':11,
          'UTF8':12,
          'RELATIVE_OID':13,
          'SEQUENCE':16,
          'SET':17,
          'NUMERIC_STRING':18,
          'PRINTABLE_STRING':19,
          'T61STRING':20,
          'VIDEOTEXT_STRING':21,
          'IA5STRING':22,
          'UTC_TIME':23,
          'GENERALIZED_TIME':24,
          'GRAPHIC_STRING':25,
          'VISIBLE_STRING':26,
          'GENERAL_STRING':27,
          'UNIVERSAL_STRING':28,
          'CHARACTER_STRING':29,
          'BMP_STRING':30,
          'LONG_FORM':31}

dict_RES={'success':0,
          'operationsError':1,
          'protocolError':2,
          'timeLimitExceeded':3,
          'sizeLimitExceeded':4,
          'compareFalse':5,
          'compareTrue':6,
          'authMethodNotSupported':7,
          'strongerAuthRequired':8,
          'referral':10,
          'adminLimitExceeded':11,
          'unavailableCriticalExtension':12,
          'confidentialityRequired':13,
          'saslBindInProgress':14,
          'noSuchAttribute':16,
          'undefinedAttributeType':17,
          'inappropriateMatching':18,
          'constraintViolation':19,
          'attributeOrValueExists':20,
          'invalidAttributeSyntax':21,
          'noSuchObject':32,
          'aliasProblem':33,
          'invalidDNSyntax':34,
          'aliasDereferencingProblem':36,
          'inappropriateAuthentication':48,
          'invalidCredentials':49,
          'insufficientAccessRights':50,
          'busy':51,
          'unavailable':52,
          'unavailable':52,
          'unwillingToPerform':53,
          'loopDetect':54,
          'namingViolation':64,
          'objectClassViolation':65,
          'notAllowedOnNonLeaf':66,
          'notAllowedOnRDN':67,
          'entryAlreadyExists':68,
          'objectClassModsProhibited':69,
          'affectsMultipleDSAs':71,
          'other':80 }


dict_APP= {'bindRequest': 0,
           'bindResponse':1,
           'unbindRequest':2,
           'searchRequest':3,
           'searchResultEntry':4,
           'searchResultDone':5,
           'modifyRequest':6,
           'modifyResponse':7,
           'addRequest':8,
           'addResponse':9,
           'delRequest':10,
           'delResponse':11,
           'modifyDNRequest':12,
           'modifyDNResponse':13,
           'compareRequest':15,
           'compareResponse':16,
           'abandonRequest':17,
           'extendedRequest':18,
           'extendedResponse':19,
           'intermediateResponse':20 }        

class bindReq:
    def __init__(self):
        self.messageId=0    
        self.code=0
        self.version=3
        self.name=""
        self.authentication=""

class LDAPResult:
    def __init__(self):
        self.messageId=0
        self.code=0
        self.result=0
        self.matchedDN=""
        self.errorMSG=""
        
class searchReq:
    def __init__(self):
        self.messageId=0     
        self.code=0
        self.objectName=0
        self.scope=3
        self.derefAliases=0
        self.sizeLimit=1
        self.timeLimit=0
        self.typesOnly=False
        self.filter=[]

class searchRes:        
    def __init__(self):
        self.messageId=0
        self.code=0
        self.objectName=""
        self.attributes=[]

class modifyReq:
    def __init__(self):
        self.messageId=0
        self.code=0
        self.objectName=""
        self.operation=[]
        self.modification=[]
        self.controls=[]
        
class addReq:
    def __init__(self):
        self.messageId=0
        self.code=0
        self.objectName=""
        self.attributes=""
        
class delReq:
    def __init__(self):
        self.messageId=0
        self.code=0
        self.objectName=""
        
#-----------------------------------------------------------------------------
# From RFC:
#- Only the definite form of length encoding is used.
#- OCTET STRING values are encoded in the primitive form only.
#- If the value of a BOOLEAN type is true, the encoding of the value octet is 
#  set to hex "FF".
#- If a value of a type is its default value, it is absent. Only some BOOLEAN
#  and INTEGER types have default values
#- These restrictions do not apply to ASN.1 types encapsulated inside of 
#  OCTET STRING values, such as attribute values, unless otherwise stated.

#-----------------------------------------------------------------------------
#Encoding section
#-----------------------------------------------------------------------------
    
# Pack according to ASN.1  (Abstract Syntax Notation One)
# Basic Encoding Rules to get identifier from Class(cls), Variable-Type(pc) and Data-Type (tag)
# see dict_class, dict_pc, dict_tag for values
def BERencode(cls,pc,tag):
    enc=cls+pc+tag
    return "%02X"%int(enc)

# Encode <value> as int with <op> identifier
# Reduce len if possible  
def encodeInt(op,value):
    ilen=4
    r=struct.pack("!I",int(value)).encode("hex")
    while r[:2]=='00':
        r=r[2:]
        ilen-=1
        if ilen==1:
            break
    ret=op+'%02X'%ilen+r
    return ret

# Encode <value> as string with <op> identifier    
def encodeStr(op,value):
    ret=op
    if len(value)<128:
        ret=ret+"%02X"%len(value)
    else:
        ret=ret+"82"+"%04X"%len(value)
    ret=ret+value.encode("hex")
    return ret

# Encode Value 
def encodeValue(op,value):
    cls,pc,tag=BERdecode(op.decode("hex"))
    if tag in [1,2,10]:
        # Encode integer
        return encodeInt(op,value)
    else:
        return encodeStr(op,value)

# Encode key=value pair (everything is as string from LDIF)
def encodeKeyValue(key,value):
    k=encodeStr('04',key).decode('hex')
    if isinstance(value,list):
        v=''
        for vv in value:
            v=v+encodeStr('04',vv).decode('hex')
    else:
        v=encodeStr('04',value).decode('hex')
    ret=encodeStr('30',k+encodeStr('31',v).decode('hex'))
    return ret
    
#-----------------------------------------------------------------------------
#Decoding section
#-----------------------------------------------------------------------------
    
# Decode according to ASN.1
def BERdecode(byte):
    cls=ord(byte)>>6
    pc=(ord(byte)>>5)&1
    tag=ord(byte)&0x1F
    return cls<<6,pc<<5,tag
    
# Decode Integer value    
def decodeToInt(msg):
    while len(msg)<8:
        msg="00"+msg
    ret=struct.unpack("!I",msg.decode("hex"))[0]
    return ret

# Decode msg header of LDAP message till msg specific stuff
def decodeHDR(msg):
    # Remove main envelope #30
    op,msg,x=chop_BER(msg)
    # get msgId
    op,msgId,msg=chop_BER(msg)
    #get appId
    appId,msg,x=chop_BER(msg)
    return msgId,appId,msg,x

# For tuple (t) decode value (default decoding method is as string)    
def decodeValue(t):
    if isinstance(t,tuple):
        (op,value)=t
    else:
        return ''
    cls,pc,tag=BERdecode(op.decode("hex"))
    if tag in [1,2,10]:
        # Decode Integer
        return decodeToInt(value)
    else:
        return value.decode("hex")


# Decode application-specific attributes (hex message-undecoded) into tuples    
def decodeParams(msg):
    ret=[]
    while msg!='':
        #print "I",msg
        op,value,msg=chop_BER(msg)
        cls,pc,tag=BERdecode(op.decode("hex"))
        #print "D",op,value,msg
        if pc==0:   #PRIMITIVE
            ret.append((op,value))
        else:
            ret.append(decodeParams(value))
        #print "R",ret
    return ret

# Decode key=[multiple values] from list    
def decodeList(list):
    vRet=''
    #print "DL",list
    if len(list)==0:
        return ERROR
    key=decodeValue(list[0])
    for v in list[1]:
        if vRet=='':
            vRet=decodeValue(v)
        else:
            vRet+=','+decodeValue(v)
    return key+'='+str(vRet)
    
# Decode to proper object (match option to attribute)    
def decodeFinal(msgId,appId,rest,unknown):
    cls,pc,tag=BERdecode(appId.decode("hex"))
    if tag==0:  # bindReq
        return decode_bindReq(msgId,appId,rest)
    if tag==1:  # bindRes
        return decode_bindRes(msgId,appId,rest)
    if tag==2:  # unbindReq
        return decode_unbindReq(msgId,appId,rest)
    if tag==3:  # searchReq
        return decode_searchReq(msgId,appId,rest)
    if tag==4:  # searchResEntry
        return decode_searchResEntry(msgId,appId,rest)
    if tag in [5,7,9,11]:  # generic LDAP response
        return decode_LDAPResult(msgId,appId,rest)
    if tag==6:  # modifyReq
        return decode_modifyReq(msgId,appId,rest,unknown)
    if tag==8:  # addReq
        return decode_addReq(msgId,appId,rest,unknown)
    if tag==10:  # deleteReq
        return decode_deleteReq(msgId,appId,rest,unknown)        
    dbg="Don't know how to process AppId",tag
    bailOut(dbg)

def decode_bindReq(msgId,appId,rest):
    L=bindReq()
    L.messageId=msgId
    L.code=appId
    #split options
    list=decodeParams(rest)
    # And place them into matching variables
    L.version=decodeValue(list.pop(0))
    L.name=decodeValue(list.pop(0))
    L.authentication=decodeValue(list.pop(0))
    return L
        
def decode_bindRes(msgId,appId,rest):    
    L=LDAPResult()
    L.messageId=msgId
    L.code=appId
    #split options
    list=decodeParams(rest)
    # And place them into matching variables
    L.result=decodeValue(list.pop(0))
    L.matchedDN=decodeValue(list.pop(0))
    L.errorMSG=decodeValue(list.pop(0))    
    return L
        
def decode_unbindReq(msgId,appId,rest):
    L=LDAPResult()
    L.messageId=msgId
    L.code=appId
    return L  
        
def decode_searchReq(msgId,appId,rest):
    L=searchReq()
    L.messageId=msgId
    L.code=appId
    #print "R",rest
    # get operation parameters
    op,value,msg=chop_BER(rest) 
    L.objectName=decodeValue((op,value))
    op,value,msg=chop_BER(msg) 
    L.scope=decodeValue((op,value))
    op,value,msg=chop_BER(msg) 
    L.derefAliases=decodeValue((op,value))
    op,value,msg=chop_BER(msg) 
    L.sizeLimit=decodeValue((op,value))           
    op,value,msg=chop_BER(msg) 
    L.timeLimit=decodeValue((op,value))
    op,value,msg=chop_BER(msg) 
    L.typesOnly=decodeValue((op,value))
    # Filter is something I never used, so - not implemented/tested
    list=decodeParams(msg)
    #print "FL",len(list),list
    if isinstance(list[0],tuple):
        L.filter.append(decodeList(list))
    else:
        for l in list:
            r=decodeList(l)
            if r!=ERROR:
                L.filter.append(r)
    return L
    
def decode_searchResEntry(msgId,appId,rest):
    L=searchRes()
    L.messageId=msgId
    L.code=appId
    #get objectName
    op,value,msg=chop_BER(rest)
    L.objectName=decodeValue((op,value))
    #print "I",msg
    # get operation parameters
    op,msg,x=chop_BER(msg)
    #print "M",msg
    #print "X",x
    # Finally split options
    list=decodeParams(msg)
    #print "L",list
    # And place them into matching variables
    for l in list:
        L.attributes.append(decodeList(l))
    return L   
        
def decode_LDAPResult(msgId,appId,rest):
    L=LDAPResult()
    L.messageId=msgId
    L.code=appId
    #split options
    list=decodeParams(rest)
    # And place them into matching variables
    L.result=decodeValue(list.pop(0))
    L.matchedDN=decodeValue(list.pop(0))
    L.errorMSG=decodeValue(list.pop(0))
    return L

def decode_modifyReq(msgId,appId,rest,unknown):
    L=modifyReq()
    L.messageId=msgId
    L.code=appId
    #get objectName
    op,op,msg=chop_BER(rest)
    L.objectName=op.decode("hex")
    # get operation parameters
    op,msg,x=chop_BER(msg)
    # Finally split options
    list=decodeParams(msg)
    #print "L",list
    # And place them into matching variables
    for l in list:
        op=decodeValue(l.pop(0))
        L.operation.append(op)
        L.modification.append(decodeList(l.pop(0)))
    # I have no idea if this controls works as it should
    if len(unknown)>0:
        list=decodeParams(unknown)
        #print "CL",list
        for l in list[0]:
            L.controls.append(decodeValue(l.pop(0)))
    return L
    
def decode_addReq(msgId,appId,rest,unknown):
    L=addReq()
    L.messageId=msgId
    L.code=appId
    #get objectName
    op,op,msg=chop_BER(rest)
    L.objectName=op.decode("hex")
    # get operation parameters
    op,msg,x=chop_BER(msg)
    # Finally split options
    list=decodeParams(msg)
    print "L",list
    # And place them into matching variables
    return L

def decode_deleteReq(msgId,appId,rest,unknown):
    L=searchReq()
    L.messageId=msgId
    L.code=appId
    #get objectName
    op,op,msg=chop_BER(rest)
    L.objectName=op.decode("hex")
    # get operation parameters
    op,msg,x=chop_BER(msg)
    # Finally split options
    list=decodeParams(msg)
    print "L",list
    return L    
            
#-----------------------------------------------------------------------------
#Misc section
#-----------------------------------------------------------------------------

# Calculate object len (currently supports up to 64K)
def calc_len(len):
    if len<=127:
        #short form
        ret="%02X"%int(len)
    else:
        #long form limited to 2 bytes (64K)
        if len<256:
            ret="0x81"+"%02X"%int(len)
        else:
            ret="0x82"+"%04X"%int(len)
    return ret
    
# Quit program with error
def bailOut(msg):
    print msg
    sys.exit(1)
    
# Split message into parts (remove field from remaining body)
def chop_msg(msg,size):
    return (msg[0:size],msg[size:])

# Chop len from message
def chop_len(msg):
    (mlen,msg)=chop_msg(msg,2)
    if mlen>"80":
        # Multibyte
        nlen=ord(mlen.decode("hex"))&0x7f
        (mlen,msg)=chop_msg(msg,2*nlen)
    return (decodeToInt(mlen),msg)

# get BER encoded option from message    
def chop_BER(msg):
    (op,msg)=chop_msg(msg,2)
    (oplen,msg)=chop_len(msg)
    (val,msg)=chop_msg(msg,2*oplen)
    return op,val,msg


# Connect to host:port (TCP) 
def Connect(host,port):
    # Create a socket (SOCK_STREAM means a TCP socket)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock

# From dict_* (dictionary) find index for value    
def dictCmd2Name(dictionary,value):
    keys=dictionary.keys()
    values=dictionary.values()
    index=[i for i,x in enumerate(values) if x == value]
    return keys[index[0]]
    
#-----------------------------------------------------------------------------
#Create section
#-----------------------------------------------------------------------------

# Create generic Response message    
def create_LDAPResult(msgId,code,result,matchedDN,errorMSG):
    # Adding from end to the beginning
    #    LDAPResult ::= SEQUENCE {
    #         resultCode         ENUMERATED,
    #         matchedDN          LDAPDN,
    #         diagnosticMessage  LDAPString,
    #         referral           [3] Referral OPTIONAL }             
    # 04="%02X"%dict_tag['OCTET_STRING']    
    # 0A="%02X"%dict_tag['ENUMERATED']
    ret=''
    ret=encodeValue('04',errorMSG)+ret
    ret=encodeValue('04',matchedDN)+ret
    ret=encodeValue('0A',result)+ret
    ret=encodeStr(code,ret.decode("hex"))
    ret=encodeStr('02',msgId.decode("hex"))+ret
    ret=encodeStr('30',ret.decode("hex"))
    return ret

######################################################        
# History
# 0.2.9 - Oct 11, 2012 - initial version
# 0.3.0 - Oct 26, 2012 - finally got it working
#       - Oct 29, 2012 - msgId encoding fixed, reuseaddr fixed
#                      - encodeTo<Type> renamed to encode<Type> (more logical)
#                      - multiple values for key now supported
#                      - int len now not fixed
# 0.3.1 - Nov 05, 2012 - comments added, code cleanup
#                      - logging removed because it conflicts with threaded
#                        LDAP simulator
#                      - add/delete/modify support
#         Nov 17, 2012 - decode rewrite