
# Configuration module for HSS Tools

# path to pyprotosim library and tools, diameter dictonary
pyprotosim_lib_path = "./pyprotosim"
# where dictDiameter.xml and other dict*.xml is stored
pyprotosim_dict_path = pyprotosim_lib_path

Common_params = {
           # DRA/HSS peer to connect
    "HOST":"10.0.0.0",
    "PORT":3868,

    # SRC address to use (host where script is running)
    "SRC_HOST":"10.0.0.0",
    "SRC_PORT":3868,

    # diameter params
    "ORIGIN_HOST":"as.ims.mnc000.mcc000.3gppnetwork.org",
    "ORIGIN_REALM":"ims.mnc000.mcc000.3gppnetwork.org",

    # if HSS behind DRA, then dest_host shouldn't be used
#    "DEST_HOST":"hss11.ims.mnc000.mcc000.3gppnetwork.org",
    "DEST_REALM":"ims.mnc000.mcc000.3gppnetwork.org",

    # is used to construct public identity in requests
    "IMPU_domain":"@ims.mnc000.mcc000.3gppnetwork.org",
    "IMPI_domain":"@ims.mnc000.mcc000.3gppnetwork.org",

    # template how full IMPU & IMPI should be constructed
    "IMPU_format": "sip:+{IDENTITY}{IMPU_domain}",
    "IMPI_format": "{IDENTITY}{IMPI_domain}",
    "TEL_format":"tel:+{IDENTITY}"          
                 
                 }

Sh_params = Common_params.copy()

# parameter for Sh interface connection
Sh_params.update ( {

# you can also customize host/port here

#                    "HOST":"10.2.26.210",
#                    "PORT":3866,
#                    "SRC_HOST":"10.2.26.254",
#                    "SRC_PORT":3868,

                    # Sh App Id
                    "APPLICATION_ID":16777217,
                    "VENDOR_ID":10415,
                    "Product_Name":"TAS",
                    #3GPP Vendor id
                    "Supported_Vendor_Id":10415,
                
                    # HSS Notif-Eff support - not supported yet
#                    "NotifEff":False,
                
                
                # CMD dict defines command-line parameter and corresponding diameter CMD
                    "CMD" : {
                             "UDR":"User-Data",
                             "SNR":"Subscribe-Notifications",
                             "PUR":"Profile-Update"
                    }
                    })

# make a copy of Sh options for Cx
Cx_params=Sh_params.copy()

# and Zh
Zh_params=Cx_params.copy()

# customize it
# remove dest_host if defined in Sh
#Cx_params.pop("DEST_HOST")
Cx_params.update( {
                   "APPLICATION_ID":16777216,
                   "VENDOR_ID":10415,
#                    "SRC_HOST": "10.0.0.0",
#                    "PORT": 3868,
#                    "ORIGIN_HOST": "scscf.ims.mnc000.mcc000.3gppnetwork.org",
                    "Server-Name":"sip:scscf.ims.mnc000.mcc000.3gppnetwork.org:5070",

# CMD dict defines command-line parameter and corresponding diameter CMD
                    "CMD": {
                            "MAR":"Multimedia-Auth",
                            "SAR":"Server-Assignment",
                            "LIR":"Location-Info",
                            "UAR":"User-Authorization"
                            }
                   } )

# customize it

#Zh_params.pop("DEST_HOST")

# delete Server-Name AVP from Zh params
#Zh_params.pop("Server-Name")
# OR redefine it below

Zh_params.update ( { 
                    "APPLICATION_ID":16777221,
                    "VENDOR_ID":10415,
                    "ORIGIN_HOST":"bsf.ims.mnc000.mcc000.3gppnetwork.org",
                    "Server-Name":"agw.ims.tele2.ru",

# CMD dict defines command-line parameter and corresponding diameter CMD
                    "CMD": {
                            "MAR":"Multimedia-Auth"
                            }

                    })

conn_params={
    "Sh":Sh_params,
    "Cx":Cx_params,
    "Zh":Zh_params
}

# list equivalent to ALL alias
ALL_SI_items = 'MMTEL-Services,IMS-ODB-Information,IMS-CAMEL-Services,MMTEL-Custom-Services,CM_SUBPROFILE,RMS_DYNAMIC_DATA'

# definition of all supported data-references for Sh
# all items exept last one must be list of dict!
# you can extend this array by defining other Data-References
# according to 3GPP TS 29.328 table 7.6.1
UDR_Template ={

#UserState is requires msisdn, doesn't work now
    "UserState":[{
            "Data-Reference":15
        }],

    "IMSUserState":[{
            "Data-Reference":11
        }],

    "CSCF":[{
            "Data-Reference":12
        }],

    "MSISDN":[{
            "Data-Reference":17
        }],

#T-ADS Information
    "TADS":[{
            "Data-Reference":26
        }],

    "STN-SR":[{
            "Data-Reference":27
        }],

# UE-SRVCC- Capability
    "SRVCC":[{
            "Data-Reference":28
        }],
# CSRN
    "CSRN":[{
            "Data-Reference":30
        }],

# CS Location Information
    "Location":[{
# Data-Reference: LocationInformation (14)
            "Data-Reference":14
# Requested-Domain: CS-Domain (0)
            ,"Requested-Domain": 0
# Current-Location: DoNotNeedInitiateActiveLocationRetrieval (0)
            ,"Current-Location": 0
# Serving-Node-Indication: ONLY_SERVING_NODES_REQUIRED (0)
            ,"Requested-Nodes": 0
        }],
# active Location retrival
    "LocationAct":[{
# Data-Reference: LocationInformation (14)
            "Data-Reference":14
# Requested-Domain: CS-Domain (0)
            ,"Requested-Domain": 0
# Current-Location: DoNotNeedInitiateActiveLocationRetrieval (0)
        # 1 - active location retrival
            ,"Current-Location": 1
# Serving-Node-Indication: ONLY_SERVING_NODES_REQUIRED (0)
            ,"Requested-Nodes": 0
        }],

# this must be dict!
    "RepositoryData":{
# Data-Reference: RepositoryData (0)
            "Data-Reference":0
        }
}

SNR_Template = {
# only RepositoryData is supported for SNR
# this must be dict!
    "RepositoryData":{
# Data-Reference: RepositoryData (0)
            "Data-Reference":0
            ,"Subs-Req-Type":0 # 0 = subscribe
            ,"Send-Data-Indication":1 # repository data request
        }
}

##### Cx

# {IMPU}
# {TEL}
# {IMPI}
# "User-Name" : "IMPI"
# "Public-Identity" : "IMPU"
# "Public-Identity" : "sip:IMPI"

Templates_Cx = {
               "MAR": {
                       "3GPP-SIP-Number-Auth-Items" : 1
                       ,"Public-Identity" : "{IMPU}"
#                       "Public-Identity" : "{TEL}",
                       ,"User-Name" : "{IMPI}"                       
                       },
               
               "SAR": {
                        "3GPP-SIP-Number-Auth-Items" : 1
                    # REGISTRATION (1)
                        ,"Server-Assignment-Type" : 1
                    # USER_DATA_NOT_AVAILABLE (0)
                        ,"User-Data-Already-Available" : 0
                        ,"Public-Identity" : "{IMPU}"
#                       "Public-Identity" : "{TEL}",
                       ,"User-Name" : "{IMPI}"
                       },
               
               "LIR": {
                       "Public-Identity" : "{IMPU}",
#                       "Public-Identity" : "{TEL}",
                       "User-Name" : "{IMPI}"
                       },
                
                "UAR": {
                       "Public-Identity" : "{IMPU}",
                       "User-Name" : "{IMPI}",
                       "Visited-Network-Identifier" : "ims.mnc000.mcc000.3gppnetwork.org",
                       # 0 -REGISTRATION
                       "User-Authorization-Type" : 0                        
                        }
               }

# Zh
Templates_Zh = {
                "MAR": {
                       "3GPP-SIP-Number-Auth-Items" : 1
                       ,"Public-Identity" : "{IMPU}"
                       ,"User-Name" : "{IMPI}"                       
                       }
                }

Templates = {
             "Cx": Templates_Cx,
             "Sh": {
                   "UDR":UDR_Template,
                   "SNR":SNR_Template
                   },
             "Zh": Templates_Zh
             }

SAR_FileName = "SAR_UD"

# print out the following XML element decoded
CSLocation_Elements = ['ServiceAreaId','LocationAreaId','CellGlobalId','LocationNumber','VLRNumber','MSCNumber']

# print formated XML on screen
PRINT_PRETTY_XML=True

# SI data file
DATA_FILE = "data/{SI}"


### Logging

# log filename
# {module} will be replaced by programm name
LOG = "log/log_{module}.log"

# old log files count
LOG_count = 5
# max log size in bytes
LOG_size = 1*(1024*1024)

########## DO NOT EDIT BELOW THIS LINE ###########

import logging
config_logger = logging.getLogger('hss_tools.config')


# Let's assume that my Diameter messages will fit into 32k
MSG_SIZE=32767

def config_dump(key=None):
    config_logger.debug("Configuration dump:")
    config_logger.debug("Conn params: %s",conn_params)
    config_logger.debug("UDR: %s",UDR_Template)
    config_logger.debug("SNR: %s",SNR_Template)
    config_logger.debug("CS Loc: %s",CSLocation_Elements)
    config_logger.debug("MSG Size: %s",MSG_SIZE)
    if (key): config_logger.debug("Module config: %s",conn_params[key])

if __name__ == "__main__":
    config_logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    config_logger.addHandler(ch)

    config_dump()

