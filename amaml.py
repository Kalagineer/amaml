###############################################################################
# amaml.py
# -----------------------------------------------------------------------------
# Description: 
# 
# ----------------------------------------------------------------------------
# Usage: 
#
###############################################################################


###############################################################################
#
# MODULES & CONSTANTS
#
#
###############################################################################

import datagen as dg

import os
import joblib
import pyfiglet


class colors:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

MAX_LENGTH=80

###############################################################################
# 
# FUNCTIONS
#
#
#
###############################################################################

###############################################################################
#
#
def printAMAML():
    amaml_header = pyfiglet.Figlet(font='roman')
    ascii_amaml = amaml_header.renderText('AMAML')
    divider = "=" * MAX_LENGTH
    subtitle="<:: Automatic Malware Analysis using Machine Learning ::>"
    
    print("\n" + divider)
    print(ascii_amaml)
    print(divider)
    print(subtitle.center(MAX_LENGTH))
    print(divider)



###############################################################################
#
#
#
def filePicker():
    print ("-- FILE SELECTION--".center(MAX_LENGTH))
    file_flag=False

    # Menu loop.
    while file_flag == False:
        file_name= input("\nPlease introduce the file that will be analyzed: ")
        
        # Let's check if it exists.
        if not os.path.exists(file_name):
            print("   > The file does not exist." 
                + "[" + colors.RED + "ERROR" + colors.END +"]")
            
            abort_response= input("Do you want to try again? [y/N] ").strip().lower()
            
            if abort_response == 'n':
                print("   > AMAML is closing... Farewell!\n")
                exit (1)
        else:
            print ("   > %s will be analyzed." % (file_name) 
                + "[" + colors.GREEN + "OK" + colors.END +"]\n")
            file_flag=True

    return file_name

def fileAnalyzer(pe_data):
    print ("-- FILE ANALYSIS--".center(MAX_LENGTH))

    analysis_flag = False





    

###############################################################################
# 
# MAIN
#
#
#
###############################################################################


if __name__ == '__main__':
    printAMAML()

    # Ask for filename
    file_name=filePicker()

    # PE data extraction
    pe_info=dg.PESqueezer(file_name)

    # PE data preparation
    del pe_info[:2]             # First two values
    del pe_info[-1]             # Last value

    # Menu for Machine Learning

    fileAnalyzer(pe_info)

    # Load 

    # Menu for Malcore

    # End
