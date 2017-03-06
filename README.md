# HSS Tools
A set of useful tools to generate requests towards EPC or IMS HSS.  
Copyright (c) 2015-2017 Denis Gudtsov
Project page: https://github.com/dgudtsov/hsstools

Uses part of  Python Protocol Simulator project (c) Sergej Srepfler code - https://sourceforge.net/projects/pyprotosim/


The following interfaces and commands are supported:
 - Sh: UDR, SNR, PUR
 - Cx: LIR, UAR, MAR, SAR
 - Zh: MAR

# Install
1. download archive
2. unzip in
3. ensure the following directory structure:

./hsstools  
|-- conf  
|-- lib  
|-- log  
|-- pyprotosim  

conf - where config file is stored  
lib - program libraries  
log - where log files are generated  
pyprotosim - external Python Protocol Simulator tool  
4. chmod a+x *.py  

## Prerequisite
Python 2 version >= 2.6.6  
Python 3 is not supported  

# Configure
Edit file conf/config_diam.py :  
1. setup hosts, ports, realms for HSS diameter connection  
2. define IMPI and IMPU domains, check IMPU and IMPI formats  
3. point out pyprotosim_lib_path to directory where pyprotosim project files are located  
Please note, i already included pyprotosim files into package.

# Usage

## Sh
```
Format: ./Sh.py COMMAND MSISDN DATA  
COMMAND: one of UDR, PUR, SNR  
MSISDN: msisdn of the subscriber, without +  
DATA: Data-reference name OR Service-Indicator name of repository data  

DATA possible values are: ['STN-SR', 'MSISDN', 'TADS', 'SRVCC', 'Location', 'IMSUserState', 'LocationAct', 'CSRN', 'CSCF', 'UserState', 'RepositoryData']  
Service-Indicator any that's present in HSS,e.g: MMTEL-Services, IMS-ODB-Information, IMS-CAMEL-Services
OR special value 'ALL' can be used (see below)
```
Examples:  
- to read RepositoryData  
example: ./Sh.py UDR 79999999999 MMTEL-Services  
example: ./Sh.py UDR 79999999999 MMTEL-Services,IMS-CAMEL-Services  
example: ./Sh.py UDR 79999999999 ALL  
ALL means: MMTEL-Services,IMS-ODB-Information,IMS-CAMEL-Services,MMTEL-Custom-Services,CM_SUBPROFILE,RMS_DYNAMIC_DATA  

- to request specific data:  
example: ./Sh.py UDR 79999999999 Location
```xml
<Sh-Data>
  <CSLocationInformation>
    <LocationNumber>
      xxx=
    </LocationNumber>
    <LocationAreaId>
      xxx=
    </LocationAreaId>
    <VLRNumber>
      <Address>
        xxx==
      </Address>
    </VLRNumber>
    <MSCNumber>
      <Address>
        xxx==
      </Address>
    </MSCNumber>
    <AgeOfLocationInformation>
      52
    </AgeOfLocationInformation>
  </CSLocationInformation>
</Sh-Data>
```
and then decoded values follows:
```
decoding LocationAreaId
result (MCC|MNC_LAI_CGI): 250f00_6004_
LocationAreaId xxx= 250f006004
decoding LocationNumber
result (MCC|MNC_LAI_CGI): 400004_5002_
LocationNumber xxx= 4000045002
decoding VLRNumber
result: 1xxxf
VLRNumber xxx== 1970000000001f
decoding MSCNumber
result: 1xxxf
MSCNumber xxx== 1970000000001f
```

example: ./Sh.py UDR 79999999999 TADS
```xml
<Sh-Data>
  <Extension>
    <Extension>
      <Extension>
        <TADSinformation>
          <IMSVoiceOverPSSessionSupport>
            1
          </IMSVoiceOverPSSessionSupport>
          <RATtype>
            1004
          </RATtype>
        </TADSinformation>
      </Extension>
    </Extension>
  </Extension>
</Sh-Data>
```

- to update data  
example: ./Sh.py PUR 79999999999 MMTEL-Services  

- How to update user-data with blank value?  
1) prepare xml profile without ServiceData element, like:  
```xml
<?xml version="1.0" encoding="UTF-8"?>
<Sh-Data>
  <RepositoryData>
    <ServiceIndication>YOUR_Service_Indicator</ServiceIndication>
    <SequenceNumber>2</SequenceNumber>
  </RepositoryData>
</Sh-Data>
```
and save it into file named "YOUR_Service_Indicator". You may don't care about 
SequenceNumber value, cause it is calculating automatically during update  

2) run PUR command:  
./Sh.py PUR 79999999999 YOUR_Service_Indicator  

- How to manage xml profiles?  
1) run UDR request, e.g.:  
./Sh.py PUR 79999999999 MMTEL-Services  

new file MMTEL-Services will be created with MMTel xml profile  

2) use xmllint tool to pretty format xml and save result into MMTEL-Services.xml:  
xmllint --format MMTEL-Services >MMTEL-Services.xml  

3) make changes:  
vim MMTEL-Services.xml  

4) convert pretty formated xml into simplified version, back from MMTEL-Services.xml :  
xmllint --noblanks MMTEL-Services.xml >MMTEL-Services  

5) run PUR, it will read MMTEL-Services as input data :  
./Sh.py PUR 79999999999 MMTEL-Services  

## Cx
```
Format: ./Cx.py COMMAND IMSI MSISDN [AUTH]
COMMAND: MAR, UAR, SAR, LIR
IMSI: imsi of the subscriber
MSISDN: msisdn of the subscriber
AUTH (optional, only for MAR is required): SIP, AKA, NONE, Unknown

IMPI and IMPU are constructed from IMSI/MSISDN
```

Examples:
- to request SIP-Digest auth scheme
example: ./Cx.py MAR 250009999999999 1234567 SIP

- to request Digest-AKA auth scheme
example: ./Cx.py MAR 250009999999999 1234567 AKA

- to allow HSS select default auth scheme
example: ./Cx.py MAR 250009999999999 1234567 Unknown

- to request Cx user profile
example: ./Cx.py SAR 250009999999999 1234567
profile will be displayed on screen and stored into ./data/SAR_UD file

- to request CSCF where subscriber is registered or unreg service for subscriber
example: ./Cx.py LIR 250009999999999 1234567
server-name or server-capabilities will be displayed on screen

- to request PSI service number
to request PSI you need to uncomment "Public-Identity" : "{TEL}" in Cx config and comment out "Public-Identity" : "{IMPU}" and User-Name
example: ./Cx.py LIR 0 1234567
imsi is not required for PSI

## Zh
```
Format: ./Zh COMMAND IMSI MSISDN [AUTH]
COMMAND: MAR
IMSI: imsi of the subscriber
MSISDN: msisdn of the subscriber
AUTH (optional, only for MAR is required): SIP, AKA, NONE, Unknown

IMPI and IMPU are constructed from IMSI/MSISDN
```
Examples:
- to request SIP-Digest auth scheme
example: ./Zh MAR 250009999999999 1234567 SIP

- to request Digest-AKA auth scheme
example: ./Zh MAR 250009999999999 1234567 AKA

- to allow HSS select default auth scheme
example: ./Zh MAR 250009999999999 1234567 Unknown

- The syntax of Zh request are fully equivalent to Cx MAR
example: ./Cx.py MAR 250009999999999 1234567 AKA
