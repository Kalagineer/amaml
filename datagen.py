###############################################################################
# datagen.py
# -----------------------------------------------------------------------------
# Written by: José Pérez Vidal
# -----------------------------------------------------------------------------
# Description: this script generates a [filename].csv file which gathers all 
# the data collected in the following directories:
#   - ./benign   - Contains benign PE files.
#   - ./mal      - Contains malicious PE files.
# 
# ----------------------------------------------------------------------------
# Usage: python3.py [filename]
###############################################################################


###############################################################################
#
# MODULES
#   - csv.    Module used to create and manipulate .csv files. 
#   - pefile. Module used as a Portable Executable (PE) reader.
#   - glob.   Module used to work around filenames.
#   - sys.    Module providing several functions and variables to manipulate
#             Python's runtime enviroment.
#   - pathvalidate. Library to sanitize a string such as filenames and paths.
#
###############################################################################

import csv
import pefile
import os
import sys
import pathvalidate


###############################################################################
# 
# FUNCTIONS
#
###############################################################################


###############################################################################
# Name: printError
#------------------------------------------------------------------------------
# Description: function used to provide useful information about the error
#              that has risen.
#------------------------------------------------------------------------------
# Parameters:
#    - error [STR]. String specifying the error.
#------------------------------------------------------------------------------
# Output: printed error message.
#
def printError(error):
    print("--------------------------------------------\n")
    print(error+"\n")
    print("Use: python3 datagen.py [filename]\n")
    print("--------------------------------------------\n")


###############################################################################
# Name: PESqueezer
#------------------------------------------------------------------------------
# Description: provides an array with all the PE headers extracted out from
#              the given file.
#------------------------------------------------------------------------------
# Parameters:
#    - file. PE file to be used.
#    - type. Last value of the array. 0 as benign software. 1 for malware.
#            Default value set to 0.           
#------------------------------------------------------------------------------
# Output: array with PE Header info.
#
def PESqueezer(file, type=0):
    pe = pefile.PE(file)
    rowPE = []
    
    rowPE.append(os.path.basename(file))
    rowPE.append(pe.FILE_HEADER.Machine)
    
    rowPE.append(str(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
    rowPE.append(str(pe.OPTIONAL_HEADER.SizeOfCode))
    rowPE.append(str(pe.FILE_HEADER.Characteristics))
        
    rowPE.append(str(pe.OPTIONAL_HEADER.MajorLinkerVersion))
    rowPE.append(str(pe.OPTIONAL_HEADER.MinorLinkerVersion))
    rowPE.append(str(pe.OPTIONAL_HEADER.SizeOfCode))
    rowPE.append(str(pe.OPTIONAL_HEADER.SizeOfInitializedData))
    rowPE.append(str(pe.OPTIONAL_HEADER.SizeOfUninitializedData))
    rowPE.append(str(pe.OPTIONAL_HEADER.BaseOfCode))
    rowPE.append(str(pe.OPTIONAL_HEADER.ImageBase))
    rowPE.append(str(pe.OPTIONAL_HEADER.FileAlignment))
    rowPE.append(str(pe.OPTIONAL_HEADER.SizeOfImage))
    rowPE.append(str(pe.OPTIONAL_HEADER.SizeOfHeaders))
    
    rowPE.append(str(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion))
    rowPE.append(str(pe.OPTIONAL_HEADER.MinorOperatingSystemVersion))
    rowPE.append(str(pe.OPTIONAL_HEADER.MajorImageVersion))
    rowPE.append(str(pe.OPTIONAL_HEADER.MinorImageVersion))
    rowPE.append(str(pe.OPTIONAL_HEADER.MajorSubsystemVersion))
    rowPE.append(str(pe.OPTIONAL_HEADER.MinorSubsystemVersion))

   
    rowPE.append(str(pe.OPTIONAL_HEADER.SizeOfStackReserve))
    rowPE.append(str(pe.OPTIONAL_HEADER.SizeOfStackCommit))
    rowPE.append(str(pe.OPTIONAL_HEADER.SizeOfHeapReserve))
    rowPE.append(str(pe.OPTIONAL_HEADER.SizeOfHeapCommit))
       
    rowPE.append(str(pe.OPTIONAL_HEADER.LoaderFlags))
    rowPE.append(str(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes))
    rowPE.append(str(pe.OPTIONAL_HEADER.DllCharacteristics))

    rowPE.append(str(pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY
                     ['IMAGE_DIRECTORY_ENTRY_EXPORT']].VirtualAddress))
    rowPE.append(str(pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY
                     ['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress))
    rowPE.append(str(pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY
                     ['IMAGE_DIRECTORY_ENTRY_RESOURCE']].VirtualAddress))
    rowPE.append(str(pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY
                     ['IMAGE_DIRECTORY_ENTRY_EXCEPTION']].VirtualAddress))
    rowPE.append(str(pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY
                     ['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress))   

    rowPE.append(type)

    return rowPE

    

      
###############################################################################
#
# HEADERS SELECTED
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

         "ImageDirectoryEntryExport", "ImageDirectoryEntryImport",
         "ImageDirectoryEntryResource", "ImageDirectoryEntryException",
         "ImageDirectoryEntrySecurity",

         "Malflag"
         ]



###############################################################################
# 
# MAIN
#
###############################################################################

if __name__ == '__main__':

    if len(sys.argv) != 2:
        printError("Invalid number of arguments")
        sys.exit(1)

    if not pathvalidate.is_valid_filename(sys.argv[1]):
        printError("Error: invalid filename. Use another.")
        sys.exit(1)

    filename = sys.argv[1]
    filename += ".csv"

    if os.path.exists(filename):
        printError("Error: That file already exists. Try another name")
        sys.exit(1)

    if not "safe" in os.listdir() or not "danger" in os.listdir():
        print("Error: Deben existir los directorios ./safe y ./danger")
        sys.exit(1)
        

    with open (filename, "w", encoding='UTF8') as file:
        fwriter = csv.writer(file)
        fwriter.writerow(header)

        for it_file in os.listdir("./safe"):
            fpath = os.path.join("./safe", it_file)
            print(fpath)
            fwriter.writerow(PESqueezer(fpath, 0))

        for it_file in os.listdir("./danger"):
            fpath = os.path.join("./danger", it_file)
            print(fpath)
            fwriter.writerow(PESqueezer(fpath, 1))


        

    


        



