# This is the implementation of the Master TPM (connected to the CCU).
# The code given here should be used for provisioning the Master TPM, and for issuing keys.
from tpm2tools import TPM2_Provision, TPM2_CreateAsymKey, TPM2_LoadExternalPubKey, TPM2_EvictControl, TPM2_FlushContext, TPM2_LoadKey
from tpm2tools import TPM2_Getrandom, TPM2_RSAEncrypt, TPM2_Hash, TPM2_Sign, TPM2_DeleteFile, TPM2_CreateFolder, TPM2_SealObject, TPM2_UnsealObject

TPM2T_PRIMARYCTX_FILE = "primary.ctx"
TPM2T_PRIMARYCTX_PERSFILE = "persprimary.ctx"

TPM2T_PUBCTX_FOLDER = "ASYMKEYCTX"
TPM2T_PUBCTX_FILE = "pubk.ctx"
TPM2T_PRVCTX_FILE = "prvk.ctx"
TPM2T_LOADEDPUBKCTX_FILE = "loadedk.ctx"
TPM2T_PUBCTX_PERSFILE = "perspubk.ctx"

TPM2T_SYMKPUBPART = "sympub.ctx"
TPM2T_SYMKSENSPART = "symsens.ctx"

TPM2T_EXTKEYSTORE_FOLDER = "EXTKEYSTORE"
TPM2T_EXTNAME_FILE = "extkey"
TPM2T_EXTEXTENSION_FILE = ".ctx"

TPM2T_KDISTRO_FOLDER = "KDISTROKEYS"
TPM2T_KDISTROENCEX_FILE = "pkextenc"
TPM2T_KDISTROPRPUB_FILE = "pkprim_pubenc"
TPM2T_KDISTROPRSENS_FILE = "pkprim_sensenc"
TPM2T_KDISTROPRLOADED_FILE = "pkprim_loaded"
TPM2T_KDISTROSIGNEX_FILE = "sign"
TPM2T_KDISTROEXT_FILE = ".dat"

#TPM2T_SYMPUBNAME_FILE = "symkey_pub"
#TPM2T_SYMSENSNAME_FILE = "symkey_sens"
#TPM2T_SYMEXTENSION_FILE = ".ctx"
#TPM2T_SYMKEYLOADED_FILE = "loadedk"

TPM2T_MHMACKEY_FOLDER = "MHMACKEYS"

TPM2T_TEMP1_FILE = "tpmtemp1.dat"
TPM2T_TEMP2_FILE = "tpmtemp2.dat"
TPM2T_TEMP3_FILE = "tpmtemp3.dat"
TPM2T_TEMP4_FILE = "tpmtemp4.dat"
TPM2T_TEMP5_FILE = "tpmtemp5.dat"


class MasterTPM(object):
    '''
    A class that defines the basic method to set up and operate a Master TPM
    '''

    def __init__(self):
        '''
        Constructor.
        '''
        super(MasterTPM, self).__init__()

        # Define basic handlers for the primary key
        self._h_primaryk = None
        self._hp_primaryk = None # persistent
        self._f_primaryk = None

        # Define basic handlers for the public/private 
        self._h_pub_asymk = None
        self._hl_pub_asymk = None # loaded
        self._hp_pub_asymk = None # persistent
        self._h_sens_asymk = None
        self._f_asymk = None

        # Define handlers and data structures for the external keys
        self._f_ext = None
        self._ext_keys = {}
        self._ext_idx = 0

        # Define handlers and data structures for distributed keys
        self._f_kdk = None
        self._kd_keys = {}
        self._kd_idx = 0

        # Define handlers and data structure for managed hmac keys
        self._f_hmack = None
        self._hmac_keys = {}
        self._hmac_idx = 0


    def provision_master(self, folderName):
        '''
        The main Master TPM provisioning method.
        '''

        # Store the base folder and set the primary key handler
        self._f_primaryk = folderName
        self._h_primaryk = self._f_primaryk + "/" + TPM2T_PRIMARYCTX_FILE
        self._hp_primaryk = self._f_primaryk + "/" + TPM2T_PRIMARYCTX_PERSFILE

        # Also prepare the folder identifier for the external keys
        self._f_ext = self._f_primaryk + "/" + TPM2T_EXTKEYSTORE_FOLDER

        # First, flush any transient objects
        if (TPM2_FlushContext() == False):
            return False

        # Provision the primary key
        if (TPM2_Provision(self._f_primaryk, TPM2T_PRIMARYCTX_FILE) == False):
            return False

        self._f_asymk = folderName + "/" + TPM2T_PUBCTX_FOLDER
        self._h_pub_asymk = self._f_asymk + "/" + TPM2T_PUBCTX_FILE
        self._hl_pub_asymk = self._f_asymk + "/" + TPM2T_LOADEDPUBKCTX_FILE
        self._hp_pub_asymk = self._f_asymk + "/" +  TPM2T_PUBCTX_PERSFILE
        self._h_sens_asymk = self._f_asymk + "/" + TPM2T_PRVCTX_FILE

        # Next, create an exportable private/public key pair. The public key can be extracted and included in a certificate.
        # The certificate, including the public part can then be distributed and used to verify signatures.
        if (TPM2_CreateAsymKey(self._h_primaryk, self._f_asymk, TPM2T_PUBCTX_FILE, TPM2T_PRVCTX_FILE) == False):
            return False

        # Lastly, make the two prior objects persistent in the TPM
        #if (TPM2_EvictControl(self._h_primaryk, self._hp_primaryk) == False):
        #    return False

        # For the second key, we need to load it first to the TPM transient object area
        if (TPM2_LoadKey(self._h_primaryk, self._h_pub_asymk, self._h_sens_asymk, self._hl_pub_asymk) == False):
            return False

        #if (TPM2_EvictControl(self._hl_pub_asymk, self._hp_pub_asymk) == False):
        #    return False

        # Prepare the folder for the symmetric keys
        self._f_kdk = self._f_asymk + "/" + TPM2T_KDISTRO_FOLDER
        if (TPM2_CreateFolder(self._f_kdk) == False):
            return False

        # Prepare the folder for managed hmac keys
        self._f_mhmack = self._f_asymk + "/" + TPM2T_MHMACKEY_FOLDER
        if (TPM2_CreateFolder(self._f_mhmack) == False):
            return False

        return True


    def load_external_key(self, keyFileName):
        '''
        Loads an external key (as transient) and stores it in a special folder.
        '''

        # Prepare the handlers and new (internal) identifier
        self._ext_idx = self._ext_idx + 1
        self._ext_keys[self._ext_idx] = self._f_ext + "/" + TPM2T_EXTNAME_FILE + str(self._ext_idx) + TPM2T_EXTEXTENSION_FILE

        if (TPM2_LoadExternalPubKey(keyFileName, self._f_ext, "rsa", TPM2T_EXTNAME_FILE + str(self._ext_idx) + TPM2T_EXTEXTENSION_FILE) == True):
            return self._ext_idx

        return -1


    def generate_ext_sym_key(self, ext_key_idx, key_size):
        '''
        Generate a new symmetric key and seal it with the external key.
        '''

        if (ext_key_idx not in self._ext_keys):
            print("External key not found in internal keystore: " + str(ext_key_id))
            return None

        # Generate the sequence of random bytes and stores them in a given file

        # Prepare the handlers and new (internal) identifier
        #self._sym_idx = self._sym_idx + 1
        #pubk = self._f_symk + "/" + TPM2T_SYMPUBNAME_FILE + str(self._sym_idx) + TPM2T_SYMEXTENSION_FILE
        #sensk = self._f_symk + "/" + TPM2T_SYMSENSNAME_FILE + str(self._sym_idx) + TPM2T_SYMEXTENSION_FILE
        #self._sym_keys[self._sym_idx] = (pubk, sensk, None)

        # Generate a random sequence of bytes - this will constitute the new symmetric key
        randf = self._f_kdk + "/" + TPM2T_TEMP1_FILE
        if (TPM2_Getrandom(key_size, randf) == False):
            return None

        # Encrypt the key with the external key
        pubencf = self._f_kdk + "/" + TPM2T_KDISTROENCEX_FILE + str(ext_key_idx) + TPM2T_KDISTROEXT_FILE
        if (TPM2_RSAEncrypt(self._ext_keys[ext_key_idx], randf, pubencf) == False):
            return None

        # DELETE the random number from disk
        if (TPM2_DeleteFile(randf) == False):
            return None

        # Compute hash
        hashf = self._f_kdk + "/" + TPM2T_TEMP2_FILE
        ticketf = self._f_kdk + "/" + TPM2T_TEMP3_FILE
        if (TPM2_Hash(pubencf, hashf, ticketf) == False):
            return None

        # Digitally sign the result
        signf = self._f_kdk + "/" + TPM2T_KDISTROSIGNEX_FILE + str(ext_key_idx) + TPM2T_KDISTROEXT_FILE
        if (TPM2_Sign(self._hl_pub_asymk, hashf, ticketf, signf) == False):
            return None

        # DELETE the hash and the ticket from disk
        if (TPM2_DeleteFile(hashf) == False):
            return None
        if (TPM2_DeleteFile(ticketf) == False):
            return None

        return (pubencf, signf)


    def generate_sealed_sym_key(self, key_size):
        '''
        Generate a new symmetric key and seal it with our primary key. The key can later be decrypted each time it is required to be sealed with an external key.
        '''

        # Prepare the handlers and new (internal) identifier
        self._kd_idx = self._kd_idx + 1
        #pubk = self._f_symk + "/" + TPM2T_SYMPUBNAME_FILE + str(self._sym_idx) + TPM2T_SYMEXTENSION_FILE
        #sensk = self._f_symk + "/" + TPM2T_SYMSENSNAME_FILE + str(self._sym_idx) + TPM2T_SYMEXTENSION_FILE
        #self._sym_keys[self._sym_idx] = (pubk, sensk, None)

        # Generate a random sequence of bytes - this will constitute the new symmetric key
        randf = self._f_kdk + "/" + TPM2T_TEMP1_FILE
        if (TPM2_Getrandom(key_size, randf) == False):
            return -1

        pubf = self._f_kdk + "/" + TPM2T_KDISTROPRPUB_FILE + str(self._kd_idx) + TPM2T_KDISTROEXT_FILE
        sensf = self._f_kdk + "/" + TPM2T_KDISTROPRSENS_FILE + str(self._kd_idx) + TPM2T_KDISTROEXT_FILE

        # Seal the key with the primary key
        if (TPM2_SealObject(self._h_primaryk, randf, pubf, sensf) == False):
            return -1

        # DELETE the random number from disk
        if (TPM2_DeleteFile(randf) == False):
            return -1

        # Store the result
        self._kd_keys[self._kd_idx] = (pubf, sensf)

        return self._kd_idx


    def export_sealed_sym_key(self, ext_key_idx, sealed_key_idx):
        '''
        Export the given sealed key with the help of the external key.
        '''

        # Verify if everything is in place
        if (ext_key_idx not in self._ext_keys):
            print("External key not found in internal keystore: " + str(ext_key_id))
            return None
        if (sealed_key_idx not in self._kd_keys):
            print("Distributed key not found in internal keystore: " + str(sealed_key_id))
            return None

        # Get the key handlers from our internal keystore
        extk = self._ext_keys[ext_key_idx]
        (pubdk, sensdk) = self._kd_keys[sealed_key_idx]

        # First, the object needs to be loaded. We will obtain a context file.
        loadedf = self._f_kdk + "/" + TPM2T_KDISTROPRLOADED_FILE + str(sealed_key_idx) + TPM2T_KDISTROEXT_FILE
        if (TPM2_LoadKey(self._h_primaryk, pubdk, sensdk, loadedf) == False):
            return None

        # Next, proceed with the unseal operation.
        unsealed_kf = self._f_kdk + "/" + TPM2T_TEMP1_FILE
        if (TPM2_UnsealObject(loadedf, unsealed_kf) == False):
            return None

        # Now, we have the unsealed key, we can encrypt it with the public external key.
        pubencf = self._f_kdk + "/" + TPM2T_KDISTROENCEX_FILE + str(ext_key_idx) + TPM2T_KDISTROEXT_FILE
        if (TPM2_RSAEncrypt(extk, unsealed_kf, pubencf) == False):
            return None

        # DELETE the unsealed object from disk
        if (TPM2_DeleteFile(unsealed_kf) == False):
            return None

        # Compute hash
        hashf = self._f_kdk + "/" + TPM2T_TEMP2_FILE
        ticketf = self._f_kdk + "/" + TPM2T_TEMP3_FILE
        if (TPM2_Hash(pubencf, hashf, ticketf) == False):
            return None

        # Digitally sign the result
        signf = self._f_kdk + "/" + TPM2T_KDISTROSIGNEX_FILE + str(ext_key_idx) + TPM2T_KDISTROEXT_FILE
        if (TPM2_Sign(self._hl_pub_asymk, hashf, ticketf, signf) == False):
            return None

        # DELETE the hash and the ticket from disk
        if (TPM2_DeleteFile(hashf) == False):
            return None
        if (TPM2_DeleteFile(ticketf) == False):
            return None

        return (pubencf, signf)


    def generate_managed_hmak_key(self, key_idx):
        '''
        Generate a new managed HMAC key.
        '''

        if key_idx not in self._sym_keys:
            print("Unknown key with idx: " + str(key_idx))
            return False

        # Extract public and sensitive part
        (pubk,sensk) = self._sym_keys[key_idx]

        # Compute loaded key handler
        loadedk = self._f_symk + "/" + TPM2T_SYMKEYLOADED_FILE + str(key_idx) + TPM2T_SYMEXTENSION_FILE

        if (TPM2_LoadKey(self._hp_pub_asymk, pubk, sensk, loadedk) == False):
            return False

        # Store the new handler back to the keystore
        self._sym_keys[key_idx] = (pubk, sensk, loadedk)

        return True
