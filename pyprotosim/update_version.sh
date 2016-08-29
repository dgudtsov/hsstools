#!/bin/sh
NEW_VER="# Version 0.3.1, Last change on Nov 05, 2012"
NEW_DATE="# February 2012 - November 2012"
for file in `find . -name '*.py'`
do
  echo $file
  cp $file $file.old
  sed "/^# Version*/c$NEW_VER" $file.old |sed "/^# February*/c$NEW_DATE" > $file
done
