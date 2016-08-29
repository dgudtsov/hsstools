#Next two lines are to include parent directory for testing
import sys
sys.path.append("..")
# Remove them normally

import eap
import logging

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    #logging.basicConfig(level=logging.INFO)
    eap.LoadEAPDictionary("../dictEAP.xml")
    EAP=eap.EAPItem()
    # Set command code
    # Remember - Requests normally starts from AAA-> UE, so 
    # even when skipped, identity is actually an response
    EAP.cmd=eap.EAP_CODE_RESPONSE
    # Set id 
    EAP.id=1
    # Set type
    EAP.type=eap.EAP_TYPE_AKA
    # Set sub-type
    EAP.stype=eap.dictEAPSUBname2type("AKA-Identity")
    I="0031303231313131323334353631303540776c616e2e6d6e633032332e6d63633236322e336770706e6574776f726b2e6f7267"
    print len(I),len(I)/4, len(I)/8
    IDENTITY=I.decode("hex")
    EAP.avps.append(("AT_IDENTITY",IDENTITY.encode("hex")))
    Payload=eap.encode_EAP(EAP)
    print "S Payload",Payload
    # Payload now contains EAP-Payload AVP
    E=eap.decode_EAP(Payload)
    print "="*30
    print eap.getEAPCodeName(E.code)
    (et,er)=eap.getEAPTypeName(E.type)
    if er==0:
        print "Type:",et
    if E.stype!=0:
       x=eap.dictEAPSUBtype2name(E.stype)
       print "Subtype:",x
    for avp in E.avps:
       (code,data)=avp
       print code,"=",data
    print "-"*30
