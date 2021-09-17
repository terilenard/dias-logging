import os, os.path as path
import subprocess, sys

TPM2T_PATH = "" #"/snap/bin"
TPM2T_CREATEPRIMARY = TPM2T_PATH + "tpm2_createprimary" # "/tpm2-tools-alexmurray.createprimary"
TPM2T_CREATE = TPM2T_PATH + "tpm2_create" # "/tpm2-tools-alexmurray.create"
TPM2T_LOADEXTERNAL = TPM2T_PATH + "tpm2_loadexternal" # "/tpm2-tools-alexmurray.loadexternal"
TPM2T_FLUSHCONTEXT = TPM2T_PATH + "tpm2_flushcontext"
TPM2T_LOAD = TPM2T_PATH + "tpm2_load"
TPM2T_RSAENCRYPT = TPM2T_PATH + "tpm2_rsaencrypt"
TPM2T_SIGN = TPM2T_PATH + "tpm2_sign"
TPM2T_HASH = TPM2T_PATH + "tpm2_hash"

TPM2T_TCTI_ABRMD = "--tcti=tabrmd:bus_name=com.intel.tss2.Tabrmd"


def TPM2_Provision(folderName, outFileName):
    '''
    Provisions a new hierarchy of keys (the endorsemene key), and stores the context file in the given folder.
    '''

    # In case the folder already exists, do not continue
    if (path.exists(folderName)):
        print("Folder %s already exists!" % folderName)
        return False

    # Create the folder
    try:
        result = os.mkdir(folderName)
    except OSError as ex:
        print("Failed to create folder: ", folderName)
    else:
        print("Folder %s successfully created" % folderName)

    # Launch the command
    result = ''
    try:
        result = subprocess.run([TPM2T_CREATEPRIMARY, '-C', 'p', '-c', folderName + '/' + outFileName, TPM2T_TCTI_ABRMD])
    except Exception as ex:
        print("There was an error while launchnig " + TPM2T_CREATEPRIMARY)
        return False

    return True


def TPM2_CreateAsymKey(parentkFileName, pkFolderName, pubkFileName, prvkFileName):
    '''
    Create a public/private key pair, and writes the public part of the key to the given file.
    '''

    # In case the folder already exists, do not continue
    if (path.exists(pkFolderName)):
        print("Folder %s already exists!" % pkFolderName)
        return False

    # In case parent folder does not exist, do not continue
    #if (path.exists(parentkFolderName) == False):
    #    print("Folder %s does not exists!" % parentkFolderName)
    #    return False

    # Create the folder
    try:
        result = os.mkdir(pkFolderName)
    except OSError as ex:
        print("Failed to create folder: ", pkFolderName)
    else:
        print("Folder %s successfully created" % pkFolderName)

    # Launch the command
    result = ''
    try:
        result = subprocess.run([TPM2T_CREATE, '-C', parentkFileName, '-u', pkFolderName + '/' + pubkFileName, '-r', pkFolderName + '/' + prvkFileName, TPM2T_TCTI_ABRMD])
    except Exception as ex:
        print("There was an error while launchnig " + TPM2T_CREATE)
        return False

    return True


def TPM2_FlushContext():
    '''
    Remove all transient contexts.
    '''

    # Run the command
    try:
        result = subprocess.run([TPM2T_FLUSHCONTEXT, '-t', TPM2T_TCTI_ABRMD])

        if result.returncode == 0:
            return True

        return False
    except subprocess.SubprocessError as ex:
        print("There was an error while launchnig " + TPM2T_FLUSHCONTEXT)
        return False

def TPM2_LoadKey(parentFileName, pubkFileName, prvkFileName, outHFileName):
    '''
    Load the key (including public and private area) to the TPM
    '''
    try:
        result = subprocess.run([TPM2T_LOAD, '-C', parentFileName, '-u', pubkFileName, '-r', prvkFileName, '-c', outHFileName, TPM2T_TCTI_ABRMD])

        if result.returncode == 0:
            return True

        return False

    except subprocess.SubprocessError:
        print("There was an error while launchnig " + TPM2T_LOAD)
        return False

def TPM2_RSAEncrypt(keyFile, inFileName, outFileName):
    '''
    Encrypts with RSA the given file, and produces the output file.
    '''
    try:
        result = subprocess.run([TPM2T_RSAENCRYPT, '-c', keyFile, '-o', outFileName, inFileName, TPM2T_TCTI_ABRMD])
        
        if result.returncode == 0:
            return True

        return False

    except subprocess.SubprocessError:
        print("There was an error while launchnig " + TPM2T_RSAENCRYPT)
        return False

def TPM2_Sign(keyFile, inFileName, outFileName):
    '''
    Signs with RSA the given file (containing a hash), and produces the output file. It also verifies that the hash was created by the TPM.
    Ticket is ignored for now, the TPM produces errors.
    '''

    try:
        result = subprocess.run([TPM2T_SIGN, '-c', keyFile, '-o', outFileName, inFileName, TPM2T_TCTI_ABRMD])

        if result.returncode == 0:
            return True

        return False

    except subprocess.SubprocessError:
        print("There was an error while launchnig " + TPM2T_SIGN)
        return False

def TPM2_Hash(inFileName, outFileName):
    '''
    Compute the hash over the given file.
    '''
    print("Started hash")
    try:
        print("Before subproc")
        result = subprocess.run([TPM2T_HASH, '-o', outFileName, inFileName, TPM2T_TCTI_ABRMD])
        print("Result " + str(result.returncode))
        if result.returncode == 0:
            return True

        return False

    except subprocess.SubprocessError:
        print("There was an error while launchnig " + TPM2T_HASH)
        return False
