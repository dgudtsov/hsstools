# HSS Tools
A set of useful tools to generate requests towards EPC or IMS HSS.  
Copyright (c) 2015-2016 Denis Gudtsov

Use part of  Python Protocol Simulator project (c) Sergej Srepfler code - https://sourceforge.net/projects/pyprotosim/


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

## Prerequisite
Python version >= 2.6.6

# Configure

Edit conf/config_diam.py :
1. setup hosts, ports, realms for HSS diameter connection
2. define IMPI and IMPU domains
3. point out pyprotosim_lib_path to directory where pyprotosim project files are located
Please note, i already included pyprotosim files into package.

# Usage

## Sh

Format: ./Sh.py COMMAND MSISDN DATA  
COMMAND: one of UDR, PUR, SNR  
MSISDN: msisdn of the subscriber, without +  
DATA: Data-reference name OR Service-Indicator name of repository data  

DATA possible values are: ['STN-SR', 'MSISDN', 'TADS', 'SRVCC', 'Location', 'IMSUserState', 'LocationAct', 'CSRN', 'CSCF', 'UserState', 'RepositoryData']  

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

## Cx
to do

## Zh
to do
