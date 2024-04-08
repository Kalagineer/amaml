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











