#!/bin/bash

###############################################################################
#   dataparser.sh
#··············································································
#   Written by: José Pérez Vidal
#··············································································
#   Usage:  dataparser.sh [file].json
#   Output: creates a human readable file called parsed-[file].data
#           in the current working directory



#  First the existence of the file is checked
if [ -f "$1" ]; then
    data=$(cat $1)
else
    echo "The file \"$1\" doesn't exist."
    exit 1
fi


# Output file generator
output_filename="parsed-${1%.json}.data"

echo "-------------------------------------------------------------------------"
echo "   Generating file...        "
echo "   > Output filename: $output_filename "

touch $output_filename

echo "   > Input filename: $1       "
echo "-------------------------------------------------------------------------"

#db_info=$(echo "$data" | jq -r '.data')
#echo "$db_info"

# sleep 10
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
echo "-------------------------------------------------------------------------"    >> $output_filename
echo " MALCORE ANALYSIS                                                        "    >> $output_filename
echo "-------------------------------------------------------------------------"    >> $output_filename
echo " GENERAL INFORMATION                                                     "    >> $output_filename
echo "   > File type: $file_type                                               "    >> $output_filename
echo "   > Threat Score: $threat_score                                         "    >> $output_filename
echo "   > File Entropy: $file_entropy                                         "    >> $output_filename
echo "   > Malcore AI Classification: $malcore_AIClass                         "    >> $output_filename
echo "-------------------------------------------------------------------------"    >> $output_filename
echo " RICH PE DATA                                                            "    >> $output_filename
echo "   > Invalid PE Checksum: $invalid_pechecksum                            "    >> $output_filename
echo "   > Malformed Rich PE Data: $malformed_richpedata                       "    >> $output_filename
echo "   > Removed Rich PE Data: $removed_richpedata                           "    >> $output_filename
echo "-------------------------------------------------------------------------"    >> $output_filename
echo " DYNAMIC ANALYSIS DATA                                                   "    >> $output_filename
echo "   > OS used: $os_run                                                    "    >> $output_filename
echo "   > Architecture: $arch_run                                             "    >> $output_filename
echo "   > Time Stamp: $timestamp                                              "    >> $output_filename
echo "   > Total run time: $emulation_time                                     "    >> $output_filename
echo "-------------------------------------------------------------------------"    >> $output_filename
echo " YARA INFORMATION                                                        "    >> $output_filename

YARA_RULE_MAX=3

for ((i = 0; i < $YARA_RULE_MAX; i++))
do
    yara_topic=$(echo "$data" | jq -r '.data.yara_rules.results['$i']')
    yara_title=$(echo "$yara_topic" | jq -r '.[0]')
    yara_result=$(echo "$yara_topic" | jq -r '.[1]')

    echo "   > $yara_title: $yara_result                                       "    >> $output_filename
done

echo "-------------------------------------------------------------------------"    >> $output_filename



cat $output_filename