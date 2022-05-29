#!/bin/bash

cd ./src/SA/$1
make
VERSION=$(git describe --tags --abbrev=0)

# Check extension.json for required fields
HELP=$(cat extension.json | jq -M .help)
if [ "null" = "$HELP" ]; then
    echo "WARN: $1 extension.json is missing 'help' property"
    exit 1
fi
NAME=$(cat extension.json | jq -M .name)
if [ "null" = "$NAME" ]; then
    echo "WARN: $1 extension.json is missing 'name' property"
    exit 1
fi
CMD_NAME=$(cat extension.json | jq -M .command_name)
if [ "null" = "$CMD_NAME" ]; then
    echo "WARN: $1 extension.json is missing 'command_name' property"
    exit 1
fi
ENTRYPOINT=$(cat extension.json | jq -M .entrypoint)
if [ "null" = "$ENTRYPOINT" ]; then
    echo "WARN: $1 extension.json is missing 'entrypoint' property"
    exit 1
fi
DEPENDS_ON=$(cat extension.json | jq -M .depends_on)
if [ "null" = "$DEPENDS_ON" ]; then
    echo "WARN: $1 extension.json is missing 'depends_on' property"
    exit 1
fi

cat extension.json | jq ".version |= \"$VERSION\"" > ../../../SA/$1/extension.json
cd ../../../SA/$1/
cp ../../LICENSE .
MANIFEST=$(cat ./extension.json | base64 -w 0)
COMMAND_NAME=$(cat extension.json | jq -r .command_name)
tar -czvf ../../packages/$COMMAND_NAME.tar.gz .
cd ../../packages
bash -c "echo \"\" | ~/minisign -s ~/minisign.key -S -m ./$COMMAND_NAME.tar.gz -t \"$MANIFEST\" -x $COMMAND_NAME.minisig"
