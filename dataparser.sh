#!/bin/bash

###############################################################################
#   dataparser.sh
#··············································································
#   Written by: José Pérez Vidal
#··············································································
#   Usage:  dataparser.sh [file].json
#   Output: creates a human readable file called parsed-[file].data
#           in the current working directory


db=false

#  First the existence of the file is checked
if [ -f "$1" ]; then
    data=$(cat $1)
else
    echo "The file \"$1\" doesn't exist."
    exit 1
fi

###############################################################################
# Important variables
#
#
base_filename=$(basename "$1" .json)
ARCHIVE="request_files/"



# Output file generator
output_filename="${ARCHIVE}parsed-${base_filename}.data"


if [[ $db = true ]]
then
    echo "-------------------------------------------------------------------------"
    echo "   Generating file...        "
    echo "   > Output filename: $output_filename "

    touch $output_filename

    echo "   > Input filename: $1       "
    echo "-------------------------------------------------------------------------"
fi

# JSON Parsing

## General Information
file_type=$(echo "$data" | jq -r '.data.threat_summary.results.file_type')
threat_score=$(echo "$data" | jq -r '.data.threat_score.results.score')
file_entropy=$(echo "$data" | jq -r '.data.threat_score.results.signatures[1].discovered')
malcore_AIClass=$(echo "$data" | jq -r '.data.threat_score.results.signatures[5].discovered')

## Rich PE Information
invalid_pechecksum=$(echo "$data" | jq -r '.data.threat_score.results.signatures[6].discovered.invalid_rich_pe_checksum')
malformed_richpedata=$(echo "$data" | jq -r '.data.threat_score.results.signatures[6].discovered.malformed_rich_pe_data')
removed_richpedata=$(echo "$data" | jq -r '.data.threat_score.results.signatures[6].discovered.rich_data_removed')

## Dynamic Analysis
os_run=$(echo "$data" | jq -r '.data.dynamic_analysis.dynamic_analysis[0].os_run')
arch_run=$(echo "$data" | jq -r '.data.dynamic_analysis.dynamic_analysis[0].arch')
timestamp=$(echo "$data" | jq -r '.data.dynamic_analysis.dynamic_analysis[0].time_stamp')
emulation_time=$(echo "$data" | jq -r '.data.dynamic_analysis.dynamic_analysis[0].emulation_total_runtime')



echo " " > $output_filename
echo "================================================================================"     >> $output_filename
echo " MALCORE ANALYSIS                                                        "            >> $output_filename
echo "================================================================================"     >> $output_filename
echo " GENERAL INFORMATION                                                     "            >> $output_filename
echo "   > File type: $file_type                                               "            >> $output_filename
echo "   > Threat Score: $threat_score                                         "            >> $output_filename
echo "   > File Entropy: $file_entropy                                         "            >> $output_filename
echo "   > Malcore AI Classification: $malcore_AIClass                         "            >> $output_filename
echo "--------------------------------------------------------------------------------"     >> $output_filename
echo " RICH PE DATA                                                            "            >> $output_filename
echo "   > Invalid PE Checksum: $invalid_pechecksum                            "            >> $output_filename
echo "   > Malformed Rich PE Data: $malformed_richpedata                       "            >> $output_filename
echo "   > Removed Rich PE Data: $removed_richpedata                           "            >> $output_filename
echo "--------------------------------------------------------------------------------"     >> $output_filename
echo " DYNAMIC ANALYSIS DATA                                                   "            >> $output_filename
echo "   > OS used: $os_run                                                    "            >> $output_filename
echo "   > Architecture: $arch_run                                             "            >> $output_filename
echo "   > Time Stamp: $timestamp                                              "            >> $output_filename
echo "   > Total run time: $emulation_time                                     "            >> $output_filename
echo "--------------------------------------------------------------------------------"     >> $output_filename

cat $output_filename