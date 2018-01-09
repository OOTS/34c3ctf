#!/usr/bin/python3

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
import Crypto.Hash
import os.path
import zipfile


secret_key_path = "secret_key.der"
from installer import compute_hash, public_key_path, signature_filename, zip_filename



def get_key():

    if os.path.isfile(public_key_path) and \
        os.path.isfile(secret_key_path):

        with open(secret_key_path, "rb") as f:
            secret_key = RSA.importKey(f.read())

    else:

        print("generating new secret key...")

        secret_key = RSA.generate(4096)
        with open(secret_key_path, "wb") as f:
            f.write(secret_key.exportKey(format='DER'))

        public_key = secret_key.publickey()
        with open(public_key_path, "wb") as f:
            f.write(public_key.exportKey(format='DER'))

    return secret_key

# copied from
# https://stackoverflow.com/questions/458436/adding-folders-to-a-zip-file-using-python/792199#792199
# https://peterlyons.com/problog/2009/04/zip-dir-python
def zip_dir(dirPath=None, zipFilePath=None, includeDirInZip=True):

    if not zipFilePath:
        zipFilePath = dirPath + ".zip"
    if not os.path.isdir(dirPath):
        raise OSError("dirPath argument must point to a directory. "
            "'%s' does not." % dirPath)
    parentDir, dirToZip = os.path.split(dirPath)

    #Little nested function to prepare the proper archive path
    def trimPath(path):
        archivePath = path.replace(parentDir, "", 1)
        if parentDir:
            archivePath = archivePath.replace(os.path.sep, "", 1)
        if not includeDirInZip:
            archivePath = archivePath.replace(dirToZip + os.path.sep, "", 1)
        return os.path.normcase(archivePath)

    outFile = zipfile.ZipFile(zipFilePath, "w",
        compression=zipfile.ZIP_DEFLATED)
    for (archiveDirPath, dirNames, fileNames) in os.walk(dirPath):
        for fileName in fileNames:
            filePath = os.path.join(archiveDirPath, fileName)
            outFile.write(filePath, trimPath(filePath))
        #Make sure we get empty directories as well
        if not fileNames and not dirNames:
            zipInfo = zipfile.ZipInfo(trimPath(archiveDirPath) + "/")
            #some web sites suggest doing
            #zipInfo.external_attr = 16
            #or
            #zipInfo.external_attr = 48
            #Here to allow for inserting an empty directory.  Still TBD/TODO.
            outFile.writestr(zipInfo, "")
    outFile.close()

    return zipFilePath


def create_sw_update(directory, secret_key, zip_path = None):

    if zip_path is None:
        zip_path = zip_filename

    hash = compute_hash(directory + "/signed_data")
    signer = PKCS1_PSS.new(secret_key)
    signature = signer.sign(Crypto.Hash.SHA256.new(hash))

    with open(directory + "/" + signature_filename, "wb") as f:
        f.write(signature)


    zip_dir(directory, zip_path, includeDirInZip=False)
    return zip_path



if __name__ == "__main__":

    secret_key = get_key()

    create_sw_update("sw_update", secret_key)

