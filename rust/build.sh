#!/bin/bash
FILE=config.txt
BIN_V="ldk_v0.0.1"
if [ ! -e "$FILE" ];
then  bash config_binary.sh
else
  source $FILE
  if [ $VERSION == $BIN_V ];
  then echo "Version: $VERSION"
  else
       bash config_binary.sh
   fi
fi

