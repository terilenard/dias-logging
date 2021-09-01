import os, os.path as path
import subprocess, sys

TPM2T_PATH = "" #"/snap/bin"
TPM2T_CREATEPRIMARY = TPM2T_PATH + "tpm2_createprimary" # "/tpm2-tools-alexmurray.createprimary"
TPM2T_CREATE = TPM2T_PATH + "tpm2_create" # "/tpm2-tools-alexmurray.create"
TPM2T_LOADEXTERNAL = TPM2T_PATH + "tpm2_loadexternal" # "/tpm2-tools-alexmurray.loadexternal"
TPM2T_EVICTCONTROL = TPM2T_PATH + "tpm2_evictcontrol"
TPM2T_FLUSHCONTEXT = TPM2T_PATH + "tpm2_flushcontext"
TPM2T_LOAD = TPM2T_PATH + "tpm2_load"
TPM2T_GETRANDOM = TPM2T_PATH + "tpm2_getrandom"
TPM2T_RSAENCRYPT = TPM2T_PATH + "tpm2_rsaencrypt"
TPM2T_SIGN = TPM2T_PATH + "tpm2_sign"
TPM2T_HASH = TPM2T_PATH + "tpm2_hash"
TPM2T_GETRANDOM = TPM2T_PATH + "tpm2_getrandom"
TPM2T_SEAL = TPM2T_PATH + "tpm2_create"
TPM2T_UNSEAL = TPM2T_PATH + "tpm2_unseal"
TPM2T_HMAC = TPM2T_PATH + "tpm2_hmac"


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


def TPM2_CreateHMACKey(parentkFileName, pubkFileName, prvkFileName):
    '''
    Create a managed HMAC key.
    '''

        # Launch the command
    result = ''
    try:
        result = subprocess.run([TPM2T_CREATE, '-C', parentkFileName, '-G', 'hmac', '-u', pubkFileName, '-r', prvkFileName, TPM2T_TCTI_ABRMD])
    except Exception as ex:
        print("There was an error while launchnig " + TPM2T_CREATE)
        print("Exception: " + str(ex))
        return False

    return True


def TPM2_LoadExternalPubKey(pkFile, folderName, keyType, outFileName):
    '''
    Load an external public key and return the new context file.
    keyType possible values: 'aes', 'rsa', 'ecc'
    '''

    # In case the folder already exists, do not continue
    if (path.exists(folderName)):
        print("Folder %s already exists!" % folderName)
        return False


    # Create the output folder
    try:
        result = os.mkdir(folderName)
    except OSError as ex:
        print("Failed to create folder: ", folderName)
    else:
        print("Folder %s successfully created" % folderName)

    # Now run the command, external keys are loaded into the NULL hierarchy
    result = ''
    try:
        result = subprocess.run([TPM2T_LOADEXTERNAL, '-C', 'n', '-u', pkFile, '-G', keyType, '-c', folderName + '/' + outFileName, TPM2T_TCTI_ABRMD])
    except Exception as ex:
        print("There was an error while launchnig " + TPM2T_LOADEXTERNAL)
        return False

    return True


def TPM2_EvictControl(fileName, outHFileName):
    '''
    Makes a key persistent or transient.
    '''

    # Run the command
    result = ''
    try:
        result = subprocess.run([TPM2T_EVICTCONTROL, '-C', 'p', '-c', fileName, '-o', outHFileName, TPM2T_TCTI_ABRMD])
    except Exception as ex:
        print("There was an error while launchnig " + TPM2T_EVICTCONTROL)
        return False

    return True

def TPM2_FlushContext():
    '''
    Remove all transient contexts.
    '''

    # Run the command
    result = ''
    try:
        result = subprocess.run([TPM2T_FLUSHCONTEXT, '-t', TPM2T_TCTI_ABRMD])
    except Exception as ex:
        print("There was an error while launchnig " + TPM2T_FLUSHCONTEXT)
        return False

    return True

def TPM2_LoadKey(parentFileName, pubkFileName, prvkFileName, outHFileName):
    '''
    Load the key (including public and private area) to the TPM
    '''

    # Run the command
    result = ''
    try:
        result = subprocess.run([TPM2T_LOAD, '-C', parentFileName, '-u', pubkFileName, '-r', prvkFileName, '-c', outHFileName, TPM2T_TCTI_ABRMD])
    except Exception as ex:
        print("There was an error while launchnig " + TPM2T_LOAD)
        print("Exception: " + str(ex))
        return False

    return True

def TPM2_RSAEncrypt(keyFile, inFileName, outFileName):
    '''
    Encrypts with RSA the given file, and produces the output file.
    '''

    # Run the command
    result = ''
    try:
        result = subprocess.run([TPM2T_RSAENCRYPT, '-c', keyFile, '-o', outFileName, inFileName, TPM2T_TCTI_ABRMD])
    except Exception as ex:
        print("There was an error while launchnig " + TPM2T_RSAENCRYPT)
        print("Exception: " + str(ex))
        return False

    return True

def TPM2_Sign(keyFile, ticketFile, inFileName, outFileName):
    '''
    Signs with RSA the given file (containing a hash), and produces the output file. It also verifies that the hash was created by the TPM.
    Ticket is ignored for now, the TPM produces errors.
    '''

    # Run the command
    result = ''
    try:
        result = subprocess.run([TPM2T_SIGN, '-c', keyFile, '-o', outFileName, inFileName, TPM2T_TCTI_ABRMD])
    except Exception as ex:
        print("There was an error while launchnig " + TPM2T_SIGN)
        print("Exception: " + str(ex))
        return False

    return True

def TPM2_Hash(inFileName, outFileName, ticketOutFile):
    '''
    Compute the hash over the given file.
    '''

    # Run the command
    result = ''
    try:
        result = subprocess.run([TPM2T_HASH, '-o', outFileName, '-t', ticketOutFile, inFileName, TPM2T_TCTI_ABRMD])
    except Exception as ex:
        print("There was an error while launchnig " + TPM2T_HASH)
        print("Exception: " + str(ex))
        return False

    return True

def TPM2_Getrandom(byteCount, outFileName):
    '''
    Generate a sequence of random bytes and stores them in a given file.
    '''

    # Run the command
    result = ''
    try:
        result = subprocess.run([TPM2T_GETRANDOM, '-o', outFileName, str(byteCount), TPM2T_TCTI_ABRMD])
    except Exception as ex:
        print("There was an error while launchnig " + TPM2T_GETRANDOM)
        print("Exception: " + str(ex))
        return False

    return True


def TPM2_DeleteFile(fileName):
    '''
    Deletes the given file from disk.
    '''

    # Run the command
    result = ''
    try:
        result = subprocess.run(['rm', fileName])
    except Exception as ex:
        print("There was an error while launchnig 'rm' " + fileName)
        print("Exception: " + str(ex))
        return False

    return True


def TPM2_CreateFolder(folderName):
    '''
    Create the given folder.
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

    return True


def TPM2_SealObject(parentkFileName, inFile, outPublic, outSensitive):
    '''
    Seal the given object with the key.
    '''

    # Launch the command
    result = ''
    try:
        result = subprocess.run([TPM2T_SEAL, '-C', parentkFileName, '-i', inFile, '-u', outPublic, '-r', outSensitive, TPM2T_TCTI_ABRMD])
    except Exception as ex:
        print("There was an error while launchnig " + TPM2T_SEAL)
        print("Exception: " + str(ex))
        return False

    return True


def TPM2_UnsealObject(loadedObjectCtx, outFile):
    '''
    Unseal the object.
    '''

    # Launch the command
    result = ''
    try:
        result = subprocess.run([TPM2T_UNSEAL, '-c', loadedObjectCtx, '-o', outFile, TPM2T_TCTI_ABRMD])
    except Exception as ex:
        print("There was an error while launchnig " + TPM2T_SEAL)
        print("Exception: " + str(ex))
        return False

    return True


def TPM2_ComputeHMAC(keyFile, message):
    '''
    Compute the HMAC over the given message
    '''

    # Launch the command
    print("Computing the HMAC over the message: " + message)
    result = ''
    try:
        process = subprocess.Popen([TPM2T_HMAC, '-c', keyFile, '--hex', TPM2T_TCTI_ABRMD], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        process.stdin.write(message.encode('utf-8'))
        result = str(process.communicate()[0])

    except Exception as ex:
        print("There was an error while launchnig " + TPM2T_HMAC)
        print("Exception: " + str(ex))
        return None

    return result



#Unfortunately, we cannot create a symmetric key wrapped by an external key ... the TPM does not allow/support it..
#def TPM2_CreateSymKey(parentkFileName, pubpFileName, senspFileName, folderName):
#    '''
#    Create a symmetric key.
#    '''

    # Make sure that the folder exists
#    if (path.exists(folderName) == False):
        # Create the output folder
#        try:
#            result = os.mkdir(folderName)
#        except OSError as ex:
#            print("Failed to create folder: ", folderName)
#            return False

    # Launch the command
#    result = ''
#    try:
#        result = subprocess.run([TPM2T_CREATE, '-C', parentkFileName, '-G', 'aes256', '-u', pubpFileName, '-r', senspFileName, TPM2T_TCTI_ABRMD])
#    except Exception as ex:
#        print("There was an error while launchnig symmetric " + TPM2T_CREATE)
#        return False
#
#    return True
