#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - September 2012
# Version 0.2.8, Last change on Sep 25, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

import sys
import socket
import IN

if __name__ == "__main__":
    LOCAL_PORT=68
    SERVER_PORT=67
    LOCAL_IP="0.0.0.0"
    BCAST_IP="255.255.255.255"

    LISTEN_DEV="eth3"
    MSG_SIZE=2048
    ###########################################################
    Conn=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # socket is in blocking mode, so let's add a timeout
    Conn.settimeout(3)
    # Bind to Device
    Conn.setsockopt(socket.SOL_SOCKET,IN.SO_BINDTODEVICE,LISTEN_DEV+'\0')
    # Enable ReuseAddr & Broadcast
    Conn.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    Conn.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
    # Bind to Address
    Conn.bind(('', LOCAL_PORT))
    ##########################################################  
    # Create DHCP-Discovery
    MAC="E83935BDAB2A"
    msg="0101060029104a2e0004800000000000000000000000000000000000"+MAC+"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000063825363350101371801020305060b0c0d0f1011122b363c438081828384858687390204ec611100000000003030323132383130344132455d0200005e030102013c20505845436c69656e743a417263683a30303030303a554e44493a303032303031ff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    # send data
    Conn.sendto(msg.decode("hex"),(BCAST_IP,SERVER_PORT))
    Conn.close()
    # Receive response
    
    rConn=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rConn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rConn.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    #rConn.setsockopt(socket.SOL_SOCKET,IN.SO_BINDTODEVICE,LISTEN_DEV+'\0')
    rConn.bind(('',LOCAL_PORT))
    while True:
    	msg,addr = rConn.recvfrom(MSG_SIZE)
        print "Answer from "+addr[0]
    #received = rConn.recvfrom(MSG_SIZE)
    # Process response
    # Normally - this is the end.
    ###########################################################
    # And close the connection
    Conn.close()
    
    
######################################################        
# History
# 0.2.8 - May 31, 2017 - DHCP initial version




