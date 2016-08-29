#!/usr/bin/python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.3.1, Last change on Oct 30, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# Threaded LDAP Simulator build upon libLdap
# interrupt the program with Ctrl-C

#Next two lines include parent directory for where libLDAP is located
import sys
sys.path.append("..")
# Remove them if everything is in the same dir

import socket
import thread
import time
import string
import logging
from libLdap import *

UNBIND="unbindReq"

# Readable time format
def now( ):
    return time.ctime(time.time( ))               # current time on the server
    
# Process received socket connection (separate thread per socket)
def handleLDAPClient(connection,address):
    while True:                    
        #get input ,wait if no data
        data=connection.recv(BUFFER_SIZE)
        #suspect more data (try to get it all without stopping if no data)
        if len(data)==BUFFER_SIZE:
            while 1:
                try:
                    data+=connection.recv(BUFFER_SIZE, socket.MSG_DONTWAIT)
                except:
                    #error means no more data
                    break
        #no data found exit loop (posible closed socket)
        if len(data)==0:
            break
        else:
            ret=process_LDAP_request(data.encode("hex")) 
            #processing input
            if ret==UNBIND:
                break
            else:
                # This is my design error - everything should be list. 
                # But this allow processing strings as well
                if isinstance(ret,str):
                    connection.send(ret.decode("hex"))
                else:
                    for r in ret:
                        connection.send(r.decode("hex"))
    dbg="Disconnecting",address
    logging.warning(dbg)
    connection.close()

# Main loop to decode LDAP request    
def process_LDAP_request(rawdata):
    opt=decodeMSG(rawdata)
    msgId,appId,code,optList=groupPairs(opt)
    if appId==0:    # bindRequest
        return create_bindRes(msgId)
    if appId==2:    # unbindRequest
        return UNBIND
    if appId==3:    # searchRequest
        return create_searchRes(msgId,code,optList)
    if appId==7:    # modifyRequest
        return create_LDAPResult(msgId,'68',0,'','')
    if appId==9:    # addRequest
        return create_LDAPResult(msgId,'6A',0,'','')
    if appId==11:   # delRequest
        return create_LDAPResult(msgId,'6C',0,'','')
    dbg="Unknown request",appId
    bailOut(dbg)

##############
# Responses
##############

def create_bindRes(msgId):
    logging.warning("Binding")
    ret=create_LDAPResult(msgId,'61',0,'','')
    return ret
    
def create_searchEntry(msgId,list):
    # Adding attributes in order
    baseObject=list[0]
    ret=findUnique(list[1:])
    dbg="UNIQ",list[1:],ret
    logging.debug(dbg)
    ret=encodeStr('30',ret.decode('hex'))
    # skip dn: before adding
    ret=encodeStr('04',baseObject[3:])+ret
    ret=encodeStr('64',ret.decode('hex'))
    ret=encodeStr('02',msgId.decode('hex'))+ret
    ret=encodeStr('30',ret.decode("hex"))    
    return ret


# Encode properly multiple keys with same name. e.g 
#objectClass: top
#objectClass: subschema
def findUnique(list):
    keys=[]
    ret=''
    # create list of unique keys
    for l in list:
        r=l.split(':',1)
        if not r[0] in keys:
            keys.append(r[0])
    # for each key find all values
    dbg="KEYS",keys
    logging.debug(dbg)
    for k in keys:
        tmp=[]
        for l in list[:]:
            r=l.split(':',1)
            if r[0]==k:
                tmp.append(r[1])
        dbg="GROUPED",k,tmp
        logging.debug(dbg)
        ret=ret+encodeKeyValue(k,tmp)
    return ret
    
def create_searchRes(msgId,code,optList):    
    L=decodeFinal(msgId,code,optList)
    lldif=findInLdif(L.baseObject,LDIF)
    dbg="Searching for ",L.baseObject, "with scope", L.scope
    logging.info(dbg)
    ret=[]
    if len(lldif)>0:
        # Do we search for baseObject or wholeSubTree

        if L.scope==0:
            #baseObject - only top level:
            ret.append(create_searchEntry(msgId,lldif[0]))
        else:
            #wholeSubTree
            for l in lldif:
                ret.append(create_searchEntry(msgId,l))
        # SearchResDone - OK
        dbg="Matches found:",len(ret)
        logging.info(dbg)
        ret.append(create_LDAPResult(msgId,'65',0,'',''))
    else:
        # SearchResDone - No such object
        try:
           s,mDN=L.baseObject.split(',',1)
        except:
           mDN=L.baseObject
        ret.append(create_LDAPResult(msgId,'65',32,mDN,''))
    return ret    

#Version is ignored
#line that begins with a single space is a continuation of the previous (non-empty) line.
#line that begins with a pound-sign ("#", ASCII 35) is a comment line
#Load ldif file  into array of lists, each containing single object 
def loadLDIF(file):
    # Load file
    f=open(file)
    list=f.readlines()
    f.close()
    # Join splitted lines
    ret=[]
    tmp=[]
    prev=''
    START=ERROR
    # Add extra line to process last line
    list.append('')
    for line in list:
        # Remove CR/LF
        ln=line.rstrip()
        if line.startswith("dn:"):
            START=1
        if len(ln)>1:
            if ln[0]==" ":
                if ln[1].isalpha():
                    # join splitted lines (but ommit leading blank)
                    prev=prev+ln[1:]
                    ln=""
        if len(prev)!=0:
            if prev[0]!="#":
                tmp.append(removeSpaces(prev))
        else:
            START=ERROR
            if len(tmp)>0:
                ret.append(tmp)
                tmp=[]
        prev=ln
    if len(tmp)>0:
        ret.append(tmp)
    return ret
    
def removeSpaces(line):
    for x in string.whitespace:
        line = line.replace(x,"")
    return line

# Search for dn: lines and return matched objects as list of lists    
def findInLdif(value,llist):
    ret=[]
    # No spaces allowed in value for search
    what=removeSpaces(value.lower())
    for line in llist:
        # match any place in dn: line
        ll=line[0].lower()
        if ll.find(what)>ERROR:
            ret.append(line)
    return ret
                       
if __name__ == "__main__":
    # level for decoding are: DEBUG, INFO, WARNING, ERROR, CRITICAL
    # To log to a file, enable next line
    #logging.basicConfig(filename='log', level=logging.INFO)
    logging.basicConfig(level=logging.INFO)
    
    BUFFER_SIZE =1024       # Limit buffer size to detect complete message
    MAX_CLIENTS=5           # This is simulator - more makes no sense
    
    # Load ldif file
    LDIF=loadLDIF("ldap-t.ldif")
    
    # Define server host:port to use
    #HOST, PORT = "10.14.5.148", 16622
    # To bind to all local IPs, use empty string as HOST
    HOST, PORT = "", 16622
    
    #############################################################################
    # Server: spawns a thread to handle each client connection
    # threads work on standard Windows systems, but process forks do not
    #############################################################################
    # I could not get ThreadingTCPserver to work 
    
    # Create the server, binding to HOST:PORT
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # fix "Address already in use" error upon restart
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))  
    server.listen(MAX_CLIENTS)
    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    while True:
        connection, address = server.accept( )
        dbg='Connected', address,'at', now( )
        logging.warning(dbg)
        thread.start_new(handleLDAPClient, (connection,address))

    server.socket.close()

######################################################        
# History
# 0.2.9 - Oct 11, 2012 - initial version
# 0.3.0 - Oct 26, 2012 - finally got it working
#       - Oct 29, 2012 - msgId encoding fixed, reuseaddr fixed
#                      - ldif parsing changed
# 0.3.1 - Oct 06, 2012 - Threaded TCPServer (multiple connections support)
#                      - removed logging (strange issues with threaded module)
#Although logging is thread-safe, and logging to a single file from multiple 
#threads in a single process is supported, logging to a single file from 
#multiple processes is not supported
#                      - fixed bug when packing multiple objectClass (ommited first)
