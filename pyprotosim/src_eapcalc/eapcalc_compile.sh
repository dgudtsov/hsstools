#!/bin/sh
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.3.0 Last change at Oct 22, 2012
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

EAP="eap/eap_common.c"
CRYP_AES="crypto/aes-ctr.c crypto/aes-cbc.c crypto/aes-internal.c crypto/aes-internal-enc.c crypto/aes-internal-dec.c crypto/aes-encblock.c"
CRYP_SHA="crypto/sha1.c crypto/sha1-internal.c crypto/sha256.c crypto/sha256-internal.c crypto/fips_prf_internal.c"
CRYP_MIL="crypto/milenage.c"
if [ $PLATFORM = "UNIX" ]
then 
    UTL="utils/os_unix.c utils/wpabuf.c utils/wpa_debug.c"
    CFLAGS="-MMD -O2 -Wall -g"
else
    UTL="utils/os_win32.c utils/wpabuf.c utils/wpa_debug.c"
fi


gcc $CFLAGS -Iutils -Icrypto -Ieap -I. \
   eapcalc.c $EAP $CRYP_AES $CRYP_SHA $CRYP_MIL $UTL -o eapcalc

if [ $PLATFORM = "UNIX" ]
then 
    strip eapcalc
else
    strip eapcalc.exe
fi

######################################################        
# History
# Ver 0.2.5 - May 25, 2012 - Initial version
# Ver 0.2.8 - Aug 2012 - SIM calculations added
# Ver 0.3 - Oct 22, 2012 - Platform automatically recognized