#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.3.1, Last change on Nov 17, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

#Next two lines are to include parent directory for testing
import sys
sys.path.append("..")
# Remove them normally

# SMPP client - bind/submit/unbind example

from libSmpp import *
import datetime
import time

def create_bind_transmitter(seq):
    R=HDRItem()
    R.mandatory.append('system_id=OneAAA-5.0EP5')
    R.mandatory.append('password=password')
    R.mandatory.append('system_type=AAA')
    R.mandatory.append('interface_version='+chr(0x34))
    R.mandatory.append('addr_ton=0')
    R.mandatory.append('addr_npi=0')
    R.mandatory.append('address_range=')
    R.optional=[]
    R.sequence=seq
    R.result=0 #OK
    R.operation='00000002'
    return R
       
def create_submit_sm(seq):
    R=HDRItem()
    R.mandatory.append('service_type=')
    R.mandatory.append('source_addr_ton=0')
    R.mandatory.append('source_addr_npi=0')
    R.mandatory.append('source_addr=')
    R.mandatory.append('dest_addr_ton=0')
    R.mandatory.append('dest_addr_npi=0')
    R.mandatory.append('destination_addr=310050123456789')
    R.mandatory.append('esm_class=0')
    R.mandatory.append('protocol_id=0')
    R.mandatory.append('priority_flag=0')
    R.mandatory.append('schedule_delivery_time=')
    R.mandatory.append('validity_period=')
    R.mandatory.append('registered_delivery=0')
    R.mandatory.append('replace_if_present_flag=0')
    R.mandatory.append('data_coding=0')
    R.mandatory.append('sm_default_msg_id=0')
    R.mandatory.append('sm_length=28')
    R.mandatory.append('short_message=00510075006f0074006100200045')
    R.optional=[]
    R.sequence=seq
    R.result=0 #OK
    R.operation='00000004'
    return R 
    
def create_unbind(seq):
    R=HDRItem()
    R.sequence=seq
    R.result=0 #OK
    R.operation='00000006'
    return R
    
if __name__ == "__main__":
    # level for decoding are: DEBUG, INFO, WARNING, ERROR, CRITICAL
    # logging.basicConfig(filename='/path/to/your/log', level=logging.INFO)
    logging.basicConfig(level=logging.INFO)
    LoadDictionary("../dictSmpp.xml")
    ################
    #HOST="10.14.5.148"
    HOST="localhost"
    PORT=8889
    # Let's assume that my messages will fit into 4k
    MSG_SIZE=4096
    # Sequence starts with 1
    seq=1
    # Connect to server
    Conn=Connect(HOST,PORT)
    ###########################################################
    # Let's build bind
    B=create_bind_transmitter(seq)
    msg=packHdr(B)
    # send data
    Conn.send(msg.decode("hex"))
    # Receive response
    received = Conn.recv(MSG_SIZE)
    ###########################################################
    # Let's build submit
    seq+=1
    S=create_submit_sm(seq)
    msg=packHdr(S)
    # send data
    Conn.send(msg.decode("hex"))
    # Receive response
    received = Conn.recv(MSG_SIZE)
    ###########################################################
    # Let's build unbind
    seq+=1
    U=create_unbind(seq)
    msg=packHdr(U)
    # send data
    Conn.send(msg.decode("hex"))
    # Receive response
    received = Conn.recv(MSG_SIZE)
    ###########################################################    
    # And close the connection
    Conn.close()

######################################################        
# History
# Ver 0.3.1 - Nov 17, 2012 - initial version
