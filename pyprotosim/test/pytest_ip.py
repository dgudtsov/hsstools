#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.2.6 Last change at Mar 18, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

#Next two lines are to include parent directory for testing
import sys
sys.path.append("..")
# Remove them normally

# Testing handling IPv4/IPv6 adresses
from diamClient import *

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    A=AVPItem()
    addr4='1.2.3.4'
    IPv4Addr=encode_Address(A,0,addr4)
    print addr4
    print IPv4Addr
    print '='*30
    print 'Decoding'
    enc_adr=IPv4Addr[16:]+'0000'
    print enc_adr
    print decode_Address(enc_adr)
    print '='*30
    addr6='2001:470:9353:6173::2105'
    IPv6Addr=encode_Address(A,0,addr6)
    print addr6
    print IPv6Addr
    print 'Decoding'
    enc_adr=IPv6Addr[16:]
    print enc_adr
    print decode_Address(enc_adr)
    print '='*30

