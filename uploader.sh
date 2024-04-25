#!/bin/bash

db=true

#############################################################################################
# Important variables
#
apiKey="c6427e9ae9d3085bdf4727a1470d99f6761bdc4f"
url="https://api.malcore.io/api/upload"
filename=$1
output_filename="status-$1.json"

state="running"

response=$(curl -F "filename1=@$filename" -X POST -H "apiKey: $apiKey" -H "X-No-Poll: true" $url)

if [[ $db = true ]]
then
    echo " "
    echo "$response"
    echo " "
fi

uuid=$(echo "$response" | jq -r '.data.data.uuid')

if [[ $db = true ]]
then
    echo " "
    echo "$uuid"
    echo " "
fi

status=$(curl -X POST https://api.malcore.io/api/status --data "uuid=$uuid" -H "apiKey: $apiKey")


if [[ $db = true ]]
then
    echo " "
    echo "$status"
    echo " "
fi

while [[ $state = "running" ]]
do
    status=$(curl -X POST https://api.malcore.io/api/status --data "uuid=$uuid" -H "apiKey: $apiKey")
    
    if [[ $db = true ]]
    then
        echo " "
        echo "$status"
        echo " "
    fi

    state=$(echo "$status" | jq -r '.data.status')

    if [[ $db = true ]]
    then
        echo " "
        echo "$state"
        echo " "
    fi

    echo "In progress..."
    sleep 5
done

echo "The file has been analyzed."

echo " "
echo "$status"
echo " "

echo "$status" > $output_filename




