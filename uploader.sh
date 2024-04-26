#!/bin/bash


###############################################################################
#   uploader.sh
#··············································································
#   Written by: José Pérez Vidal.
#------------------------------------------------------------------------------
#   Usage: uploader.sh [file]
#   Output: creates a file in the working directory named : 
#           status-[filename].json
#
#


# Debugging flag
db=true

###############################################################################
# Important variables
#
#
apiKey="c6427e9ae9d3085bdf4727a1470d99f6761bdc4f"           
url="https://api.malcore.io/api/upload"
filename=$1
base_filename=$(basename "$filename" .exe)
output_filename="status-$base_filename.json"



state="running"

# We send the petition to malcore servers
response=$(curl -F "filename1=@$filename" -X POST -H "apiKey: $apiKey" -H "X-No-Poll: false" $url)

if [[ $db = true ]]
then
    echo " "
    echo "$response"
    echo " "
fi


# In $uuid is the extract the identifier for the scan
uuid=$(echo "$response" | jq -r '.data.data.uuid')

if [[ $db = true ]]
then
    echo " "
    echo "$uuid"
    echo " "
fi

# We receive the status of the scan
status=$(curl -X POST https://api.malcore.io/api/status --data "uuid=$uuid" \
         -H "apiKey: $apiKey")


if [[ $db = true ]]
then
    echo " "
    echo "$status"
    echo " "
fi

# We make a periodic check until the scan is done
# There is no automatic polling
while [[ $state = "running" ]]
do
    status=$(curl -X POST https://api.malcore.io/api/status --data "uuid=$uuid" \
             -H "apiKey: $apiKey")
    
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

# Once it's done we update the status
sleep 5
status=$(curl -X POST https://api.malcore.io/api/status --data "uuid=$uuid" \
         -H "apiKey: $apiKey")

echo "The file has been analyzed."

echo " "
echo "$status"
echo " "

# The file is created and written
touch $output_filename
echo "$status" > $output_filename

