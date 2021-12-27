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
TPM2T_EXTEND_PCR = TPM2T_PATH + "tpm2_pcrextend"
TPM2T_READ_PCR = TPM2T_PATH + "tpm2_pcrread"

TPM2T_TCTI_ABRMD = "--tcti=tabrmd:bus_name=com.intel.tss2.Tabrmd"


def TPM2_Provision(folderName, outFileName):
    '''
    Provisions a new hierarchy of keys (the endorsemene key), and stores the context file in the given folder.
    '''

    # In case the folder does not exists, create it
    if (not path.exists(folderName)):
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

    if not os.path.isfile(parentkFileName):
        print("Could not find: " + parentkFileName)
        return False

    # In case the folder does not exists, create it
    if (not path.exists(pkFolderName)):
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

def TPM2_Hash(inFileName, outFile):
    '''
    Compute the hash over the given file.
    '''
    try:

        result = subprocess.run([TPM2T_HASH, inFileName, "-o", outFile, "--hex",TPM2T_TCTI_ABRMD])
        if result.returncode == 0:
            return True

        return False

    except subprocess.SubprocessError:
        print("There was an error while launchnig " + TPM2T_HASH)
        return False

def TPM2_ExtendPcr(pcrIndex, digestFile):
    '''
    Extends a PCR index with the provided digest using sha-1.
    '''
    digest = ""
    try:
        digest = subprocess.run(["cat", digestFile], capture_output=True, text=True)
        print(digest.stdout)
    except subprocess.SubprocessError:
        print("There was an error while reading " + digestFile)
        return False

    args = "{}:{}={}".format(str(pcrIndex), "sha1", digest.stdout)
    try:
       
        result = subprocess.run([TPM2T_EXTEND_PCR, args])
        if result.returncode == 0:
            return True

        return False

    except subprocess.SubprocessError:
        print("There was an error while launchnig " + TPM2T_EXTEND_PCR)
        return False

def TPM2_ReadPcr(pcrIndex):
    '''
    Extends a PCR index with the provided digest using sha-1.
    '''

    args = "{}:{}".format("sha1", str(pcrIndex))
    try:
        print("Before subproc")
        result = subprocess.run([TPM2T_READ_PCR, args], capture_output=True, text=True)

        print("Result " + str(result.stdout))
        if result.returncode == 0:
            return True

        return False

    except subprocess.SubprocessError:
        print("There was an error while launchnig " + TPM2T_EXTEND_PCR)
        return False


# if __name__ == "__main__":

#     digest = TPM2_Hash("/tmp/logs.dat", "/tmp/digest.dat")
#     TPM2_ExtendPcr(4, "/tmp/digest.dat");

#     success = TPM2_Sign(TPM2_PRIV_CTX, TMP_DIGEST_FILE, TMP_OUTPUT)
#     print(str(success))