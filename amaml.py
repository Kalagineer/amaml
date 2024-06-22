###############################################################################
# amaml.py
# -----------------------------------------------------------------------------
# Written by: José Pérez Vidal
# ----------------------------------------------------------------------------
# Description: this file contains the usage of the models generated in
# amaml.ipynb and joins it with the services of Malcore. It is considered
# the "hub" of these two malware analysis technics.
#
#-----------------------------------------------------------------------------
# Usage: python3 amaml.py
###############################################################################


###############################################################################
#
# MODULES & CONSTANTS
#
###############################################################################

import datagen as dg
import tensorflow as tf
from sklearn.preprocessing import StandardScaler

import os
import glob
import joblib
import numpy as np
import subprocess as sp

import pyfiglet


# STYLE CONSTANTS

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
DIVIDER= "=" * MAX_LENGTH

###############################################################################
# 
# FUNCTIONS
#
###############################################################################

###############################################################################
# Name: printAMAML
#------------------------------------------------------------------------------
# Description: Prints the header of the script.
#------------------------------------------------------------------------------
# Parameters:       
#------------------------------------------------------------------------------
# Output: printed header.
#
def printAMAML():
    amaml_header = pyfiglet.Figlet(font='roman')
    ascii_amaml = amaml_header.renderText('AMAML')
    
    subtitle="<:: Automatic Malware Analysis using Machine Learning ::>"
    
    print("\n" + DIVIDER)
    print(ascii_amaml)
    print(DIVIDER)
    print(subtitle.center(MAX_LENGTH))
    print(DIVIDER)

###############################################################################
# Name: filePicker
#------------------------------------------------------------------------------
# Description: prompts a menu where you can select the path of the desired
#              file. Checks if it exists.
#------------------------------------------------------------------------------
# Parameters:           
#------------------------------------------------------------------------------
# Output: path to the disered file.
#
def filePicker():
    print ("-- FILE SELECTION --".center(MAX_LENGTH))
    file_flag=False

    # Menu loop.
    while file_flag == False:
        # File to be analyzed
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


###############################################################################
# Name: modelSelector
#------------------------------------------------------------------------------
# Description: prompts the menu with the current generated files in the
#              folder ./models. They can be either .pk. or .keras.
#------------------------------------------------------------------------------
# Parameters:      
#------------------------------------------------------------------------------
# Output: path of the selected model.
#
def modelSelector():
    # List of generated models
    available_models = glob.glob("models/*.pkl") + glob.glob("models/*.keras")

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

    # Selection of model
    while int(selection) < 1 or int(selection) > len(available_models):
        selection = input("\nYour decision: ")

    selected_model=available_models[int(selection)-1]

    print (f"\n   > You have chosen: {selection}) - {selected_model} "
                + "[" + colors.GREEN + "OK" + colors.END +"]\n")

    return selected_model

###############################################################################
# Name: fileAnalyzer
#------------------------------------------------------------------------------
# Description: takes the file passed by parameter and using the PESqueezer
#              function and the model selected with modelSelector()
#              the executable is analized.
#------------------------------------------------------------------------------
# Parameters:
#    - filename. Path of the file to be analized.          
#------------------------------------------------------------------------------
# Output: prompts whether it is malicious or not.
#
def fileAnalyzer(filename):
    # PE data extraction
    pe_info=dg.PESqueezer(file_name)
    scaler = StandardScaler()


    # PE data preparation
    del pe_info[:2]             # First two values
    del pe_info[-1]             # Last value
    
    pe_info = np.array(pe_info).astype(int)
    pe_info = pe_info.reshape(1,-1)

    model_to_use = modelSelector()

    print(f"   > Analyzing {filename} with {model_to_use}..." 
            + "[" + colors.GREEN + "OK" + colors.END +"]\n")
    
    prediction = 0

    # Load the model and make the prediction with the PE
    if model_to_use.endswith('.pkl'):
        model = joblib.load(model_to_use)
        prediction = model.predict(pe_info)
    elif model_to_use.endswith('.keras'):
        pe_info_fitted = scaler.fit_transform(pe_info)
        model = tf.keras.models.load_model(model_to_use)
        predictions = model.predict(pe_info_fitted, verbose=1)
        prediction = predictions[0][0]
        prediction_pc = prediction * 100
    else:
        raise ValueError(f"Unsupported file: {model_to_use}" + "[" + colors.RED +
                          "ERROR" + colors.END +"]")

    if prediction == 1:
        print(f"\n   > The file {filename} has been detected as " 
                + colors.RED + "MALICIOUS" + colors.END + ".")
        print(colors.BOLD + "\nImmediate action is recommended." + colors.END)
    elif prediction > 0:
        print(f"The chances that the file {filename} is malicious are: " + colors.RED 
              + str(prediction_pc) +" %" + colors.END)
    else:
        print(f"   > The file {filename} doesn't seem to be malicious.")
    
###############################################################################
# Name: malcoreAssistant
#------------------------------------------------------------------------------
# Description: using both ./uploader.sh and ./dataparser.sh this function
#              sends the malware selected to Malcore Servers for them to
#              analyze it.
#------------------------------------------------------------------------------
# Parameters:
#    - filename. Path of the file to be analized.          
#------------------------------------------------------------------------------
# Output: finished parsed status of the analysis.
#
def malcoreAssistant(filename):
    # Assign the uploader script and its name
    uploader_script="./uploader.sh"

    # Checking if it's there
    if not os.path.exists(uploader_script):
        print(f"> Missing {uploader_script} file." 
              + "[" + colors.RED + "ERROR" + colors.END +"]")
        exit (1)

    # Same with the parser
    parser_script="./dataparser.sh"

    if not os.path.exists(parser_script):
        print(f"> Missing {parser_script} file." 
              + "[" + colors.RED + "ERROR" + colors.END +"]")
        exit (1)
    
    print(f"   > Sending the file {filename} to Malcore..." 
          + "[" + colors.GREEN + "OK" + colors.END +"]\n")
    
    # Execute UpLoader
    ul_output=sp.run([uploader_script, filename], capture_output=True, text=True)

    path_to_dp=str(ul_output.stdout).strip()
    print(f"   > Generated {path_to_dp}... Parsing."
          + "[" + colors.GREEN + "OK" + colors.END +"]\n")

    # Execute DataParser
    dp_output=sp.run([parser_script, path_to_dp],
                        capture_output=True, text=True)

    print(str(dp_output.stdout))



###############################################################################
# Name: analyzerMenu
#------------------------------------------------------------------------------
# Description: Main function of the amaml.py that serves as a nexus to
#              the fileAnalyzer function and to the malcoreAssistant function.
#------------------------------------------------------------------------------
# Parameters:
#    - filename. Path of the file to be analized.          
#------------------------------------------------------------------------------
# Output: Control flow booleans
#
def analyzerMenu(filename):
    print(f"\nPlease choose in between these options:\n")
    print(f"   1) AMAML Models\n   2) Malcore Services\n   3) Choose another file\n"
         + "   4) Close AMAML\n")

    answer=0

    while answer <= 0 or answer > 4:
        answer=int(input("Your decision: "))

    if (answer == 1):
        fileAnalyzer(filename)
    elif (answer == 2):
        malcoreAssistant(filename)
    elif (answer == 3):
        return False, True
    elif (answer == 4):
        return True, True
    
    return False, False
        

        

###############################################################################
# 
# MAIN
#
###############################################################################


if __name__ == '__main__':
    printAMAML()

    exec_flag=False
    file_flag=False
        
    while exec_flag == False:
        file_flag=False

        # File Selector
        file_name=filePicker()

        print ("-- FILE ANALYSIS--".center(MAX_LENGTH))

        while file_flag == False:
            # File Analysis
            exec_flag, file_flag=analyzerMenu(file_name)


    print(DIVIDER)
    print("Closing AMAML... See you soon!".center(MAX_LENGTH))
    print(DIVIDER)

    exit (0)
