#!/bin/sh
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.3 Last change at Oct 22, 2012
# Automated testing tool to verify correct computations
##################################################################

# To enable shell debugging insert "set -x" where needed
# To disable shell debugging insert "set +x" where needed

# Verify that value exist
checkIfExist () {
  if [ "$1" = "$2" ] 
  then
    OK="X$OK"
  fi
#  echo "OK is ",$OK
}

# For N successful tests there should be N Xes
checkResult () {
  if [ "$2" = "$3" ]
  then
    echo "$1 PASS!!"
  else
    echo "$1 FAIL!!!!"
  fi
}

# Detect target system (currently only tested on XP)
TARGET=`set |grep "^OS="`
if [ "$TARGET" = "OS=Windows_NT" ]
then 
    # Change to calc.exe for Windows
    EXE="a3a8.exe"
else
    # Linux, Solaris
    EXE="./a3a8"
fi

#set -x
##############################
# A3/A8 calculation
##############################
K="0x22222222222222222222222222222222"
RAND="0x1234567890abcdef1234567890abcdef"
RES=`$EXE $K $RAND `
OK=""
for p in $RES
do
  checkIfExist $p "F3FC482C55C25FFACB29E800"
done
checkResult "A3A8" $OK "X"

######################################################        
# History
# Ver 0.2.8 - Aug 2012 - SIM calculations added
# Ver 0.3   - Oct 22, 2012 - Value for mac-sim was wrong

