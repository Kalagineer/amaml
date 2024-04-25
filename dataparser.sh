#!/bin/bash

###############################################################################
#   dataparser.sh
#··············································································
#


# Output file generator

data=$(cat $1)

# echo "$data"

output_filename="parsed-${1%.json}.data"

echo "-------------------------------------------------------------------------"
echo "   Generating file...        "
echo "   > Output filename: $output_filename "

touch $output_filename

echo "   > Input filename: $1       "
echo "-------------------------------------------------------------------------"

#db_info=$(echo "$data" | jq -r '.data')
#echo "$db_info"

#sleep 10
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


# len_threat_score=$(echo "$data" | jq -r '.data.threat_score.results.signatures | length')

# real_length=$((len_threat_score))


# for ((i = 0; i < $real_length; i++)); do
#     echo "Número: $(echo "$data" | jq -r '.data.threat_score.results.signatures['$i'].discovered')"
# done

cat $output_filename