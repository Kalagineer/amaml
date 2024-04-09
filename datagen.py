###############################################################################
# datagen.py
# -----------------------------------------------------------------------------
# Description: this script generates a .csv file which gathers all the data
# collected in the following directories:
#   - ./benign   - Contains benign PE files.
#   - ./mal      - Contains malicious PE files.
# 
# ----------------------------------------------------------------------------
# Usage: 
#
###############################################################################


###############################################################################
#
# MODULES
#   - csv.    Module used to create and manipulate .csv files. 
#   - pefile. Module used as a Portable Executable (PE) reader.
#   - glob.   Module used to work around filenames.
#
###############################################################################

import csv
import glob
import pefile
import os
import sys
import pathvalidate



###############################################################################
#
# HEADERS SELECTED
#
# 
#
#
###############################################################################

header = ["Name", "Machine",
        
         "AddressOfEntryPoint", "SizeOfCode", "Characteristics",
         "MajorLinkerVersion", "MinorLinkerVersion",
         "SizeOfCode", "SizeOfInitializedData", "SizeOfUninitializedData",
         "BaseOfCode", "ImageBase", "FileAlignment",
         "SizeOfImage", "SizeOfHeaders",

         "MajorOperatingSystemVersion", "MinorOperatingSystemVersion",
         "MajorImageVersion", "MinorImageVersion",
         "MajorSubsystemVersion", "MinorSubsystemVersion",

         "SizeOfStackReserve", "SizeOfStackCommit",
         "SizeOfHeapReserve", "SizeOfHeapCommit",
         
         "LoaderFlags", "NumberOfRvaAndSizes", "DllCharacteristics",
         "MalFlag"
         ]


if __name__ == '__main__':

    if len(sys.argv) != 2:
        print('Error: Invalid number of arguments\n')
        print('Use: python3 datagen.py [filename]\n')
        sys.exit(1)

    if not pathvalidate.is_valid_filename(sys.argv[1]):
        print('Error: invalid filename. Use another.\n')
        print('Use: python3 datagen.py [filename]\n')
        sys.exit(1)

    filename = sys.argv[1]
    filename += ".csv"

    with open (filename, "w", encoding='UTF8') as file:
        fwriter = csv.writer(file)
        fwriter.writerow(header)
        


        

    


        



