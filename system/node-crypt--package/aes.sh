
#!/bin/bash

if [ "$#" -ne 3 ]; then
  echo "Usage: ./app.sh [encrypt|decrypt] <file> <key>"
  exit 1
fi

command=$1
file=$2
key=$3

if [ "$command" = "encrypt" ] ; then
  node main.ts "$command" "$file" "$key"
elif  [ "$command" = "decrypt" ]; then
 node main.ts "$command" "$file" "$key"
else
  echo "Command must be 'encrypt' or 'decrypt'"
  exit 1
fi
