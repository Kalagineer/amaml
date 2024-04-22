#!/bin/bash

apiKey="f3b1c2558e07fda7534b6905273edae8361fe5b4"
url="https://api.malcore.io/api/upload"
filename="/home/pepe/Desktop/TFG/amaml/danger/0a0e9201a1a934e4ccc61a199698c34bfea35dfe.exe"

curl -F "filename1=@$filename" -X POST -H "apiKey: $apiKey" $url
