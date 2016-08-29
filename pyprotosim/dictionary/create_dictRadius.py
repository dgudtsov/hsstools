#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.2.3 Last change at Feb 25, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# levels for logging are: DEBUG, INFO, WARNING, ERROR, CRITICAL
import logging
import sys
import os

def Q(val):
    return chr(34)+val+chr(34)

def M(mandatory):
    if mandatory=='must':
       return ' mandatory='+Q(mandatory)
    else:
       return ''

def V(vendor):
   if vendor=='':
      return ''
   else:
      return ' vendor-id='+Q(vendor)

def split_line(line):
    ret=line.split()
    return ret
    
def findTypes(files):
    TYPES=[]
    for file in files:
        f=open(file,"r")
        dfile=f.readlines()
        f.close()
        for line in dfile:
            if line.startswith("ATTRIBUTE"):
                #['ATTRIBUTE', 'User-Password', '2', 'string', 'encrypt=1']
                atline=split_line(line[:-1])
                #print atline
                atype=atline[3]
                if atype not in TYPES:
                    print atline
                    TYPES.append(atype)
    print TYPES
        
# Load diameter dictionary
def LoadBaseDictionary(files):
    ATTRIBUTE=[]
    VALUE=[]
    for file in files:
        skip=0
        vId=""        
        f=open(file,"r")
        dfile=f.readlines()
        f.close()
        for line in dfile:
            if line.startswith("BEGIN-VENDOR"):
                skip=1
                continue
            if line.startswith("END-VENDOR"):
                skip=0
            if skip==0:
                if line.startswith("ATTRIBUTE"):
                    ATTRIBUTE.append(split_line(line[:-1]))
                if line.startswith("VALUE"):
                    VALUE.append(split_line(line[:-1]))
                if line.startswith("VENDOR"):
                    #['VENDOR', 'ADSL-Forum', '3561']
                    v=split_line(line[:-1])
                    msg="VENDOR",v
                    logging.debug(msg)
                    vId=v[1]
                    vCode=v[2]
                    print '<vendor code='+Q(vCode)+V(vId)+' name='+Q(vId)+' />'
    vId=""
    for attr in ATTRIBUTE:
        #['ATTRIBUTE', 'User-Password', '2', 'string', 'encrypt=1']
        Name=attr[1]
        Code=attr[2]
        Type=attr[3]
        if len(attr)>4:
            Mand=attr[4]
        else:
            Mand=""
        msg=attr,len(attr)
        logging.debug(msg)
        Enumerated=[]
        for v in VALUE:
            #['VALUE', 'Service-Type', 'Login-User', '1']
            if v[1]==attr[1]:
                eName=v[2]
                eCode=v[3]
                msg="    ",v[2:]
                logging.debug(msg)
                Enumerated.append('    <enum code='+Q(eCode)+' name='+Q(eName)+'/>')
        if len(Enumerated)==0:
            print '<avp code='+Q(Code)+V(vId)+' name='+Q(Name)+' type='+Q(Type)+M(Mand)+'/>'
        else:
            print '<avp code='+Q(Code)+V(vId)+' name='+Q(Name)+' type='+Q(Type)+M(Mand)+'>'
            for e in Enumerated:
                print e
            print '</avp>'

# Load diameter dictionary
def LoadVendorDictionaries(files):
    for file in files:
        ATTRIBUTE=[]
        VALUE=[]
        skip=0
        vId=""        
        f=open(file,"r")
        dfile=f.readlines()
        f.close()
        for line in dfile:
            if line.startswith("VENDOR"):
                #['VENDOR', 'ADSL-Forum', '3561']
                msg="VENDOR",split_line(line[:-1])
                logging.debug(msg)
                vId=(split_line(line[:-1])[1])
            if line.startswith("BEGIN-VENDOR"):
                skip=1
                continue
            if line.startswith("END-VENDOR"):
                skip=0
            if skip==1:
                if line.startswith("ATTRIBUTE"):
                    ATTRIBUTE.append(split_line(line[:-1]))
                if line.startswith("VALUE"):
                    VALUE.append(split_line(line[:-1]))

        for attr in ATTRIBUTE:
            #['ATTRIBUTE', 'User-Password', '2', 'string', 'encrypt=1']
            Name=attr[1]
            Code=attr[2]
            Type=attr[3]
            if len(attr)>4:
                Mand=attr[4]
            else:
                Mand=""
            msg=attr,len(attr)
            logging.debug(msg)
            Enumerated=[]
            for v in VALUE:
                #['VALUE', 'Service-Type', 'Login-User', '1']
                if v[1]==attr[1]:
                    eName=v[2]
                    eCode=v[3]
                    msg="    ",v[2:]
                    logging.debug(msg)
                    Enumerated.append('    <enum code='+Q(eCode)+' name='+Q(eName)+'/>')
            if len(Enumerated)==0:
                print '<avp code='+Q(Code)+V(vId)+' name='+Q(Name)+' type='+Q(Type)+M(Mand)+'/>'
            else:
                print '<avp code='+Q(Code)+V(vId)+' name='+Q(Name)+' type='+Q(Type)+M(Mand)+'>'
                for e in Enumerated:
                    print e
                print '</avp>'

if __name__ == "__main__":
    # levels for logging are: DEBUG, INFO, WARNING, ERROR, CRITICAL
    #logging.basicConfig(level=logging.DEBUG)
    # NOTE!!!!
    # Wireshark Radius dictionary returns LAST found matching definition
    # My dictionary returns first (and only) matching definition
    # So be warned when compile dictionary
    # I did it by hand with help of this tool
    DIR="./radius"
    f=open(DIR+"/dictionary","r")
    dfile=f.readlines()
    f.close()
    # Due to different idea, I need to parse thru ALL files for non-vendor parts at once
    files=[]
    for line in dfile:
        if line.startswith("$INCLUDE"):
            fname=split_line(line[:-1])
            files.append(DIR+"/"+fname[1])
    LoadBaseDictionary(files)
    LoadVendorDictionaries(files)
    findTypes(files)

######################################################        
# History
# 0.2.3 - Feb 25, 2012 - initial release 
