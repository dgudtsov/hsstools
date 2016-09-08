# HSS Tools
A set of useful tools to generate requests towards EPC or IMS HSS.  
Copyright (c) 2015-2016 Denis Gudtsov

Uses part of  Python Protocol Simulator project (c) Sergej Srepfler code - https://sourceforge.net/projects/pyprotosim/


The following interfaces and commands are supported:
 - Sh: UDR, SNR, PUR
 - Cx (work in progress): LIR, UAR, MAR, SAR
 - Zh (work in progress): MAR

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
4. chmod a+x Sh.py  

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
example: ./Sh.py UDR 79999999999 TADS  

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
to do

## Zh
to do
