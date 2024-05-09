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
    data=$(cat "$1")
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

    echo "   Generating file...        "
    echo "   > Output filename: $output_filename "

    touch "$output_filename"

    echo "   > Input filename: $1       "
fi



# JSON PARSING
echo " "                                                                                >  "$output_filename"
echo "==============================================================================="  >> "$output_filename"
echo " MALCORE ANALYSIS"                                                                >> "$output_filename"
echo "==============================================================================="  >> "$output_filename"
echo " GENERAL INFORMATION"                                                             >> "$output_filename"

## GENERAL INFORMATION

file_type=$(jq -r '.data.threat_summary.results.file_type' <<< "$data")
misc_info=$(jq -r '.data.exif_data.results.misc_information' <<< "$data")

# misc_info
linker_version=$(jq -r '.linker_version' <<< "$misc_info")
img_file_charac=$(jq -r '.image_file_characteristics' <<< "$misc_info")
subsystem=$(jq -r '.subsystem' <<< "$misc_info")

echo "   > Image File Characteristics: $img_file_charac"                                >> "$output_filename"
echo "   > Linker Version: $linker_version"                                             >> "$output_filename"
echo "   > File type: $file_type"                                                       >> "$output_filename"
echo "   > Subsystem: $subsystem"                                                       >> "$output_filename"
echo "==============================================================================="  >> "$output_filename"

## THREAT SCORE (ts)

# Avoiding these sections of analysis
SUS_ASSEMB="Suspicious Assembly"
UNK_SECTIONS="Unknown Sections"
CODE_CAVE="Code Cave"
DYN_IMPORT="Dynamic Import Loading"

echo " THREAT SCORE INFORMATION"                                                        >> "$output_filename" 

ts_data=$(jq -r '.data.threat_score.results' <<< "$data")
ts_valor=$(jq -r '.score' <<< "$ts_data")

ts_signatures=$(jq -r '.signatures' <<< "$ts_data")
length_signatures=$(jq -r '. | length' <<< "$ts_signatures")

echo "   > Threat Score: $ts_valor"                                                     >> "$output_filename"

## We loop through threat_score values
for (( i=0; i < length_signatures; i++))
do 
    # We acquire useful information about the threat_score value (signature)
    current_signature=$(jq -r --argjson i "$i" '.[$i]' <<< "$ts_signatures")
    name_current_sign=$(jq -r '.info.title' <<< "$current_signature")
    type_current_sign=$(jq -r ' .discovered | type' <<< "$current_signature")
    
    if [[ $name_current_sign != "$SUS_ASSEMB" && $name_current_sign != "$UNK_SECTIONS" \
        && $name_current_sign != "$CODE_CAVE" && $name_current_sign != "$DYN_IMPORT" ]]
    then
        echo "   > $name_current_sign"                                                  >> "$output_filename"

        # In case it's an array...
        if [[ $type_current_sign == "array" ]]
        then
            length_discovered=$(jq -r '.discovered | length' <<< "$current_signature")

            # ... we loop through it
            for (( j=0; j < length_discovered; j++ ))
            do
                current_discovered=$(jq -r --argjson j "$j" '.discovered[$j]' <<< "$current_signature")
                echo "      - $current_discovered"                                      >> "$output_filename"
            done
        elif [[ $type_current_sign == "object" ]]
        then

            # If it's an object we parse it
            current_discovered=$(jq -r '.discovered' <<< "$current_signature" \
                                | grep -o '"[^"]*": [^,}]*' | sed -e 's/"//g' -e 's/^/      - /') 
            echo "$current_discovered"                                                  >> "$output_filename"
        else
            current_discovered=$(jq -r '.discovered' <<< "$current_signature")
            echo "      - $current_discovered"                                          >> "$output_filename"
        fi
    fi
done


## Dynamic Analysis
os_run=$(echo "$data" | jq -r '.data.dynamic_analysis.dynamic_analysis[0].os_run')
arch_run=$(echo "$data" | jq -r '.data.dynamic_analysis.dynamic_analysis[0].arch')
timestamp=$(echo "$data" | jq -r '.data.dynamic_analysis.dynamic_analysis[0].time_stamp')
emulation_time=$(echo "$data" | jq -r '.data.dynamic_analysis.dynamic_analysis[0].emulation_total_runtime')

echo "==============================================================================="  >> "$output_filename"
echo " DYNAMIC ANALYSIS DATA"                                                           >> "$output_filename"
echo "   > OS used: $os_run"                                                            >> "$output_filename"
echo "   > Architecture: $arch_run"                                                     >> "$output_filename"
echo "   > Time Stamp: $timestamp"                                                      >> "$output_filename"
echo "   > Total run time: $emulation_time"                                             >> "$output_filename"
echo "==============================================================================="  >> "$output_filename"

cat "$output_filename"