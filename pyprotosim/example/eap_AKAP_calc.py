#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - March 2012
# Version 0.2.5, Last change on Mar 16, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# Calculating EAP-AKA' keys and values

#Next two lines are to include parent directory for testing
import sys
sys.path.append("..")
# Remove them normally

from libDiameter import *
import eap

if __name__ == "__main__":
    # level for decoding are: DEBUG, INFO, WARNING, ERROR, CRITICAL
    logging.basicConfig(level=logging.DEBUG)
    #LoadDictionary("../dictDiameter.xml")
    eap.LoadEAPDictionary("../dictEAP.xml")
    # Needed values are
    # Identity - from EAP-Request sent to HSS
    # RAND - from EAP-Response from HSS
    # AUTN - from EAP-Response from HSS
    # Note - if reauth is disabled, next two does not exist
    #   * IV - from EAP-Response from AAA
    #   * ENCR_DATA - from EAP-Response from AAA
    # OP - Operator-Specific Constant: from network provider (written in SIM card)
    # K  - Subscriber Secret Key: from network provider (written in SIM card)
    #================================================
    Identity="6111122223333456@nai.epc.mnc111.mcc222.3gppnetwork.org"
    OP="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    K="77777777777777777777777777777777"
    RAND = "19DA080197EC6B819DD1D6DEB50B919D"
    SQN = "000000000001"
    AMF = "3333"
    IV = ""
    ENCR_DATA = ""
    #=============================
    # Procedure
    # 1) From OP,K,RAND calculate XRES,Ck,Ik (milenage-f2345)
    # This is enough to build response, but let's calculate a bit further
    # 2) From Identity,Ck,Ik calculate keys (aka)
    # If AT_ENCR_DATA AVP exist
    #     3) Using those keys to decode AT_ENCR_DATA 
    # 4) Using OP,K,RAND,SQN,AMF calculate XMAC, MAC_S (milenage-f1) to verify AUTN
    # ============================================================
    # Step 1
    XRES,CK,IK,AK,AKS=eap.aka_calc_milenage(OP,K,RAND)
    print XRES,CK,IK,AK,AKS
    print "="*30
    # Step 2
    KENCR,KAUT,MSK,EMSK,KRE=eap.akap_calc_keys(Identity,CK,IK)
    print KENCR
    print "+"*30
    # Step 3
    # Example how to decode Reauth-Id
    DATA=eap.decrypt_data(IV,KENCR,ENCR_DATA)
    print DATA
    print "-"*30
    avps=eap.splitEAPAVPs(DATA)
    for avp in avps:
        (Name,Value)=avp
        print Name,"=",Value 
    REAUTH=findAVP("AT_NEXT_REAUTH_ID",avps)
    if REAUTH<>-1:
       print REAUTH.decode("hex")
    print "="*30
    # Step 4
    # AUTN is actually SQN xor AK + AMF + XMAC
    params="0x"+OP+" 0x"+K+" 0x"+RAND+" 0x"+SQN+" 0x"+AMF
    XMAC,MACS=eap.exec_calc("milenage-f1",params)
    print XMAC,MACS

######################################################        
# History
# 0.2.5 - May 31, 2012 - AKA Prime calc initial version
# 0.2.8 - Sep 28, 2012 - enhanced description added

