#!/bin/sh
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.3 Last change at Oct 22, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# Script to compile calc tool

# Detect target system (currently only tested on XP)
TARGET=`set |grep "^OS="`
if [ "$TARGET" = "OS=Windows_NT" ]
then 
    # Compile for Windows
    PLATFORM="WIN"
else
    # Linux, Solaris
    PLATFORM="UNIX"
fi

if [ $PLATFORM = "UNIX" ]
then 
    CFLAGS="-MMD -O2 -Wall -g"
fi

gcc $CFLAGS a3a8.c -o a3a8

if [ $PLATFORM = "UNIX" ]
then 
    strip a3a8
else
    strip a3a8.exe
fi   

######################################################        
# History
# Ver 0.2.8 - Aug 2012 - Initial version
# Ver 0.3   - Oct 22, 2012 - Platform automatically recognized