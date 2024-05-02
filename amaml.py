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
import glob
import joblib
import numpy as np
import subprocess as sp

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
    print ("-- FILE SELECTION --".center(MAX_LENGTH))
    file_flag=False

    # Menu loop.
    while file_flag == False:
        file_name= input("\nPlease introduce the file that will be analyzed: ")
        
        # Let's check if it exists.
        if not os.path.exists(file_name):
            print("   > The file does not exist." 
                + "[" + colors.RED + "ERROR" + colors.END +"]")
            
            abort_response= input("Do you want to try again?" 
                                  + "[y/N] ").strip().lower()
            
            if abort_response == 'n':
                print("   > AMAML is closing... Farewell!\n")
                exit (1)
        else: 
            print (f"   > {file_name} will be analyzed. "
                + "[" + colors.GREEN + "OK" + colors.END +"]\n")
            file_flag=True

    return file_name

def modelSelector():
    available_models = glob.glob("models/*.pkl")

    if (len(available_models) == 0):
        print("   > There are currently 0 models. " 
              + "[" + colors.RED + "ERROR" + colors.END +"]")
        exit (1)

    it = 1
    selection = 0

    print("-"*MAX_LENGTH)

    print("\nPlease choose between the following models: ")

    for model in available_models:
        print(f"   {it}) {model}")
        it += 1

    while int(selection) < 1 or int(selection) > len(available_models):
        selection = input("\nYour decision: ")

    selected_model=available_models[int(selection)-1]

    print (f"\n   > You have chosen: {selection}) - {selected_model} "
                + "[" + colors.GREEN + "OK" + colors.END +"]\n")

    return selected_model


def fileAnalyzer(filename):
    # PE data extraction
    pe_info=dg.PESqueezer(file_name)

    # PE data preparation
    del pe_info[:2]             # First two values
    del pe_info[-1]             # Last value
    
    pe_info = np.array(pe_info).astype(int)
    pe_info = pe_info.reshape(1,-1)

    print ("-- FILE ANALYSIS--".center(MAX_LENGTH))

    analyzing_flag=False
    continue_response='null'

    while analyzing_flag == False:
        model_to_use = modelSelector()

        print(f"   > Analyzing {filename} with {model_to_use}..." 
              + "[" + colors.GREEN + "OK" + colors.END +"]\n")
        
        classifier = joblib.load(model_to_use)
        prediction = classifier.predict(pe_info)

        if prediction == 1:
            print(f"   > The file {filename} has been detected as " 
                  + colors.RED + "MALICIOUS" + colors.END + ".")
            print(colors.BOLD + "\nImmediate action is recommended." + colors.END)
        else:
            print(f"   > The file {filename} doesn't seem to be malicious.")

        while continue_response != 'y' and continue_response != 'n':
            continue_response=input("\nWould like to use Malcore Services?" 
                                    + " [y/N] ").strip().lower()
                
        if continue_response == 'y':
            malcoreAssistant(filename)
    

def malcoreAssistant(filename):
    uploader_script="uploader.sh"

    if not os.path.exists(uploader_script):
        print(f"> Missing {uploader_script} file." 
              + "[" + colors.RED + "ERROR" + colors.END +"]")
        exit (1)

    parser_script="dataparser.sh"

    if not os.path.exists(parser_script):
        print(f"> Missing {parser_script} file." 
              + "[" + colors.RED + "ERROR" + colors.END +"]")
        exit (1)
    
    print(f"   > Sending the file {filename} to Malcore..." 
          + "[" + colors.GREEN + "OK" + colors.END +"]\n")
    
    op_uploader=sp.run(["./upload.sh", filename])
    dp_output=sp.run(["./dataparser.sh", "request_files/status-00b6b7e3b923861ef8c257aa3803a239ce4d6154.json"],
                        capture_output=True, text=True)

    print(str(dp_output.stdout))

    
        
        

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

    # Menu for Machine Learning

    fileAnalyzer(file_name)
