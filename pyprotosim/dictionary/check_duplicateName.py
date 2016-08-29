#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.3.1 Last change on Nov 13, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# Verify unique names in new Diameter dictionary
# Warn only - change is up to the maintainer

import xml.dom.minidom as minidom

# Load dictionary
def LoadDictionary(file):
    doc = minidom.parse(file)
    node = doc.documentElement
    dict_avps = doc.getElementsByTagName("avp")
    uniqueNames=[]
    skip=[]
    skip.append('Unassigned')
    skip.append('Experimental-Use')
    skip.append('Implementation-Specific')
    skip.append('Reserved')
    skip.append('Not defined in .xml')
    skip.append('Unallocated')
    for td in dict_avps:
        tName=td.getAttribute("name")
        tCode=td.getAttribute("code")
        tVendor=td.getAttribute("vendor-id")
        if tName in uniqueNames:
            if tName not in skip:
                print "WARNING - duplicate:",tCode,tName,tVendor
        else:
            uniqueNames.append(tName)
           
if __name__ == "__main__":
    LoadDictionary("dictDiameter.xml")

######################################################        
# History
# 0.3.1 - Nov 13, 2012 - initial release (no more manual verification)