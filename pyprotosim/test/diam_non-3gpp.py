import sys
sys.path.append("..")

from libDiameter import *
import logging

# level for decoding are: DEBUG, INFO, WARNING, ERROR, CRITICAL
#logging.basicConfig(filename='log', level=logging.INFO)
logging.basicConfig(level=logging.INFO)

LoadDictionary("../dictDiameter.xml")
AVP="000005dcc0000114000028af000001bb4000002c000001bc4000001731323131313232323230303036323300000001c24000000c00000000000005ddc0000010000028af00000000000005dec0000010000028af000000000000007c40000010000000000000000100000596c000009c000028af0000058fc0000010000028af00000001000001ed4000000a61310000000005b0c0000010000028af000000000000059bc000002c000028af00000204c0000010000028af000001f400000203c0000010000028af000001f400000597c0000038000028af00000404c0000010000028af000000010000040ac000001c000028af00000416c0000010000028af000000000000058fc0000010000028af00000000"
#non3gpp=decodeAVP(AVP)
print AVP
#print non3gpp
print "="*30
test=encodeAVP('Non-3GPP-User-Data', [
        encodeAVP('Subscription-Id', [
            encodeAVP('Subscription-Id-Data', '121112222000623'),
            encodeAVP('Subscription-Id-Type', 0)]), 
        encodeAVP('Non-3GPP-IP-Access', 0),
        encodeAVP('Non-3GPP-IP-Access-APN', 0),
        encodeAVP('MIP6-Feature-Vector', 1),
        encodeAVP('APN-Configuration', [
            encodeAVP('Context-Identifier', 1), 
            encodeAVP('Service-Selection', 'a1'), 
            encodeAVP('PDN-Type', 0), 
            encodeAVP('AMBR', [
                encodeAVP('Max-Requested-Bandwidth-UL', 500), 
                encodeAVP('Max-Requested-Bandwidth-DL', 500)
            ]), 
            encodeAVP('EPS-Subscribed-QoS-Profile', [
                encodeAVP('QoS-Class-Identifier', 1), 
                encodeAVP('Allocation-Retention-Priority', [
                    encodeAVP('Priority-Level', 0)
                ])
            ])
        ]),
        encodeAVP('Context-Identifier', 0)
    ])

print test
non3gpp=decodeAVP(test)
print non3gpp
sys.exit()
print '+'*30
test=encodeAVP('Non-3GPP-User-Data', [
        encodeAVP('Subscription-Id', [
            encodeAVP('Subscription-Id-Data', '121112222000623'),
            encodeAVP('Subscription-Id-Type', 0)]), 
        encodeAVP('Non-3GPP-IP-Access', 0),
        encodeAVP('Non-3GPP-IP-Access-APN', 0),
        encodeAVP('MIP6-Feature-Vector', 1),
        encodeAVP('APN-Configuration', [
            encodeAVP('Context-Identifier', 1), 
            encodeAVP('Service-Selection', 'a1'), 
            encodeAVP('PDN-Type', 0), 
            encodeAVP('AMBR', [
                encodeAVP('Max-Requested-Bandwidth-UL', 500), 
                encodeAVP('Max-Requested-Bandwidth-DL', 500)]), 
            encodeAVP('EPS-Subscribed-QoS-Profile', [
                encodeAVP('QoS-Class-Identifier', 1), 
                encodeAVP('Allocation-Retention-Priority', [
                    encodeAVP('Priority-Level', 0)])])]),
        encodeAVP('Context-Identifier', 0)])  
print test
non3gpp=decodeAVP(test)
print non3gpp
