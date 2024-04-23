######################################
#
#   dataparser.sh
#

data=$(cat $1)
output_filename="parsed-${1%.json}.data"

echo "-------------------------------"
echo "   Generating file...        "
echo "   > Output filename: $output_filename "

touch $output_filename

echo "   > Input filename: $1       "
echo "-------------------------------"


file_type=$(echo "$data" | jq -r '.data.threat_summary.results.file_type')
threat_score=$(echo "$data" | jq -r '.data.threat_score.results.score')
file_entropy=$(echo "$data" | jq -r '.data.threat_score.results.signatures[1].discovered')
malcore_AIClass=$(echo "$data" | jq -r '.data.threat_score.results.signatures[5].discovered')



echo " " > $output_filename
echo "----- MALCORE SUMMARY ------"         >> $output_filename
echo "   > File type: $file_type"           >> $output_filename
echo "   > Threat Score: $threat_score"     >> $output_filename
echo "   > File Entropy: $file_entropy"     >> $output_filename
echo "   > Malcore AI Classification: $malcore_AIClass"     >> $output_filename

# len_threat_score=$(echo "$data" | jq -r '.data.threat_score.results.signatures | length')

# real_length=$((len_threat_score))


# for ((i = 0; i < $real_length; i++)); do
#     echo "Número: $(echo "$data" | jq -r '.data.threat_score.results.signatures['$i'].discovered')"
# done

cat $output_filename