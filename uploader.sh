#!/bin/bash

#############################################################################################
# Important variables
#
apiKey="21d6295d73722b2dd88acf93f58c4bcfcb705d61"
url="https://api.malcore.io/api/upload"
filename="/home/pepe/Desktop/TFG/amaml/danger/a684bc249fdcaaae006ab429d046c28147ae7430.exe"

state="running"

response=$(curl -F "filename1=@$filename" -X POST -H "apiKey: $apiKey" -H "X-No-Poll: true" $url)
uuid=$(echo "$response" | jq -r '.data.data.uuid')
status=$(curl -X POST https://api.malcore.io/api/status --data "uuid=$uuid" -H "apiKey: $apiKey")

while [[ $state = "running" ]]
do
    status=$(curl -X POST https://api.malcore.io/api/status --data "uuid=$uuid" -H "apiKey: $apiKey")
    state=$(echo "$status" | jq -r '.data.status')
    echo "In progress..."
    sleep 5
done

echo "The file has been analyzed."

echo "$status" > status_2.json

#fileType=$(echo '$status' | jq -r '.data.threat_summary.results.file_type')
#fileThreatScore=$(echo '$status' | jq -r '.data.threat_score.results.score')
#fileEntropy=$(echo '$status' | jq -r '.data.threat_score.results.signatures[2]')
#fileAIClass=$(echo '$status' | jq -r '.data.threat_score.results.signatures[9]')



#echo "RESULT:"
#echo "The file type is: $fileType"
#echo "The overall Threat Score is: $fileThreatScore"
#echo "The level of entropy of the file is: $fileEntropy"
#echo "The AI Classification done by Malcore is: $fileAIClass"


# shell commands for debugging pourposes
#
# curl -X POST https://api.malcore.io/api/status --data "uuid=6e18915d06977e20-2fa4f1ad-a8c944db-ef3e1a06-12ab6293-8a95241b6b23f929" -H "apiKey: 21d6295d73722b2dd88acf93f58c4bcfcb705d61"
# cat status_1.json | jq -r '.data.threat_score.results.signatures' | length



