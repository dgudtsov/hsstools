#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - September 2012
# Version 0.2.8, Last change on Sep 28, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# Calculating EAP-SIM keys and values 
# HLR/HSS keys can be calculated from A3A8 function using COMP128

#Next two lines are to include parent directory for testing
import sys
sys.path.append("..")
# Remove them normally

from libRadius import *
import eap

def prepareKeysFromTriplets(a1,a2,a3):
    #a=Authentication-Information-SIM
    #Treat as String, not hex
    #47fccae1253d85d2+fb86d937+cbfe6115271cc21db2d3e000
    rand=a1[0:16]+a2[0:16]+a3[0:16]
    kc=a1[16:24]+a2[16:24]+a3[16:24]
    return rand,kc

if __name__ == "__main__":
    # level for decoding are: DEBUG, INFO, WARNING, ERROR, CRITICAL
    logging.basicConfig(level=logging.DEBUG)
    eap.LoadEAPDictionary("../dictEAP.xml")
    # Needed values are
    # Identity           - from EAP-Request sent to HLR(HSS)/from EAP-Payload sent to AAA
    # 3xRAND,3xKC        - from EAP-Response from HLR(HSS) or a3a8 output
    # NONCE_MT           - from EAP-Payload sent to AAA
    # SELECTED_VER       - from EAP-Payload sent to AAA
    # VERSION_LIST       - from EAP-Payload sent to client
    # 
    # Note - if reauth is disabled, next two does not exist
    #   * IV        - from EAP-Response from AAA
    #   * ENCR_DATA - from EAP-Response from AAA
    #
    # Note: If COMP128-1 is used for a3a8, you can use included function to calculate keys
    # K  - Subscriber Secret Key: from network provider (written in SIM card)
    #================================================
    Identity="1385913234960000"
    K="77777777777777777777777777777777"
    NONCE_MT="3333333333333333ffffffffffffffff"
    IV = "053cdf774f7067508504358f0f6756da"
    VERSION_LIST="0001"
    SELECTED_VER="1"
    ENCR_DATA = "ba7781b70f414e1ebcca9caf68d049a20be84dff9602b81e0b71a4df9b41b57a843616b36348fedc49be1d7304c176d1c5e0b2b69f0985d788aad0fcc2e147daaff7e9ce5d0989367fb2ac0d091ad6eb34ecd3759c9a84571174477fe4bd468281d0f5981d42f2a48381f7885ea30dca"
    #=============================
    # Procedure
    # 1) From K,RAND calculate SRES,KC (a3a8)x3 or copy values from HSS response
    # 2) From Identity,3*KC,NONCE_MT,VERSION_LIST,SELECTED_VERSION calculate keys (sim)
    # If AT_ENCR_DATA AVP exist
    #     3) Using those keys to decode AT_ENCR_DATA 
    # ============================================================
    # Step 1
    #SRES,KC=eap.sim_calc_a3a8(RAND,K)
    #print RAND,SRES,KC
    # Copied from SIP-Auth-Data-Item->Authentication-Information-SIM(301)
    a1="343766636361653132353364383564326662383664393337636266653631313532373163633231646232643365303030".decode("hex")
    a2="663065366339636161643166353733613832616137356665363066343666353965346331396335393936316161633030".decode("hex")
    a3="323534333064306365383134306564656238386464653763303135326432343235386261656331386330386331633030".decode("hex")
    # Copied from SIP-Auth-Data-Item->Authorization-Information-SIM(302)
    b1="6639333733396536"
    b2="3937356635386534"
    b3="3737343362623433"
    SRES=b1+b2+b3
    RAND,KC=prepareKeysFromTriplets(a1,a2,a3)
    print RAND,SRES,KC
    print "RAND=",RAND.encode("hex")
    print "KC=",KC.encode("hex")
    print "="*30
    # Step 2
    KENCR,KAUT,MSK,EMSK,MK=eap.sim_calc_keys(Identity,KC.encode("hex"),NONCE_MT,VERSION_LIST,SELECTED_VER)
    # KAUT is used to sign AT_MAC
    # Step 3 (optional)
    DATA=eap.decrypt_data(IV,KENCR,ENCR_DATA)
    print DATA
    print "-"*30
    avps=eap.splitEAPAVPs(DATA)
    for avp in avps:
        (Name,Value)=avp
        print Name,"=",Value 
    REAUTH=findAVP("AT_NEXT_REAUTH_ID",avps)
    if REAUTH<>ERROR:
       print REAUTH.decode("hex")
    print "="*30

######################################################        
# History
# 0.2.8 - Sep 28, 2012 - SIM calc explained initial version

