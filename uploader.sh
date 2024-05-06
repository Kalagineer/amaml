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
db=false

###############################################################################
# Important variables
#
#
apiKey="0263afac30771ac92bfe9643bed84bafc116e5d0"           
url="https://api.malcore.io/api/upload"
filename=$1
base_filename=$(basename "$filename" .exe)

output_filename="status-$base_filename.json"
ARCHIVE="request_files/"
output_path=$ARCHIVE$output_filename



state="running"
ERROR_CODE="error code: 522"
response=$ERROR_CODE

# We send the petition to malcore servers
while [[ $response == "$ERROR_CODE" ]]
do
    response=$(curl -s -F "filename1=@$filename" -X POST -H "apiKey: $apiKey" -H "X-No-Poll: true" $url)
done

if [[ $db = true ]]
then
    echo " "
    echo "Showing response:"
    echo "$response"
    echo " "
fi


# In $uuid is the extract the identifier for the scan
uuid=$(echo "$response" | jq -r '.data.data.uuid')

if [[ $db = true ]]
then
    echo " "
    echo "Showing UUID:"
    echo "$uuid"
    echo " "
fi



# We make a periodic check until the scan is done
# There is no automatic polling
while [[ $state == "running" ]]
do
    status=$(curl -s -X POST https://api.malcore.io/api/status --data "uuid=$uuid" \
             -H "apiKey: $apiKey")
    
    if [[ $db = true ]]
    then
        echo " "
        echo "Showing status:"
        echo "$status"
        echo " "
    fi


    if [[ $status != "$ERROR_CODE" ]]
    then
        state=$(echo "$status" | jq -r '.data.status')
    fi

    if [[ $db = true ]]
    then
        echo " "
        echo "Showing state:"
        echo "$state"
        echo " "
    fi


    if [[ $db = true ]]
    then
    echo "In progress..."
    fi
    sleep 5
done

# Once it's done we update the status
sleep 5

status=$(curl -s -X POST https://api.malcore.io/api/status --data "uuid=$uuid" \
         -H "apiKey: $apiKey")

if [[ $db = true ]]
then
    echo "The file has been analyzed."
fi

if [[ $db = true ]]
then
    echo " "
    echo "Showing status (2):"
    echo "$status"
    echo " "
fi

# The file is created and written
touch $ARCHIVE$output_filename
echo "$status" > $output_path

echo "$output_path"

