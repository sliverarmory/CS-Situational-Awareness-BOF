#!/bin/bash

cd ./src/SA/$1
make
VERSION=$(git describe --tags --abbrev=0)
cat extension.json | jq ".version |= \"$VERSION\"" > ../../../SA/$1/extension.json

cd ../../../SA/$1/
cp ../../LICENSE .
MANIFEST=$(cat ./extension.json | base64 -w 0)
COMMAND_NAME=$(cat extension.json | jq -r .command_name)
tar -czvf ../../packages/$COMMAND_NAME.tar.gz .
cd ../../packages
bash -c "echo \"\" | ~/minisign -s ~/minisign.key -S -m ./$COMMAND_NAME.tar.gz -t \"$MANIFEST\" -x $COMMAND_NAME.minisig"
