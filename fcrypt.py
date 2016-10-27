import sys
import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

# This function encrypts the data given in the input plaintext file to the cipher text file.
def encryption(destination_public_key_filename,sender_private_key_filename,input_plaintext_file,ciphertext_file):
    # Get the Keys
    public_key = load_public_key(destination_public_key_filename)
    private_key = load_private_key(sender_private_key_filename)
    try:
        plaintext = open(input_plaintext_file, 'r').read().rstrip('\n')
    except:
        print "Cannot find input text file: "+input_plaintext_file
        sys.exit()
    output_file = open(ciphertext_file, 'w')

    # Create a random session key and initialization vector
    session_key = os.urandom(32)
    iv = os.urandom(16)

    # Encrypt session key using SHA1 OAEP public key crypto
    cipher = public_key.encrypt(
                session_key+iv,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA1(),
                    label=None))
    output_file.write(base64.b64encode(cipher)+'\n')

    # Encrypt plaintext using AES symmetric encryption
    padder = PKCS7(128).padder()
    padded_data = padder.update(plaintext)
    plaintext = padded_data + padder.finalize()
    cipher =  Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext) + encryptor.finalize()
    ciphertext = base64.b64encode(ct)
    output_file.write(ciphertext+'\n')

    # Sign the message
    signature_msg = os.urandom(64)
    signer = private_key.signer(
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),hashes.SHA256()
    )
    signer.update(signature_msg)
    signature = signer.finalize()
    output_file.write(base64.b64encode(signature_msg) + '\n')
    output_file.write(base64.b64encode(signature))
    print "Message Encrypted"

# This function loads the public key. Key should be in pem format.
def load_public_key(key_name):
    try:
        with open(key_name, "rb") as key_file:
            final_key = serialization.load_pem_public_key(
                key_file.read(),
                backend = default_backend()
            )
    except(RuntimeError, TypeError, NameError):
        print "Unable to open public key: "+key_name
        sys.exit()
    return final_key

# This function loads the private key. Key should be in pem format.
def load_private_key(key_name):
    try:
        with open(key_name, "rb") as key_file:
            final_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend = default_backend()
            )
    except(RuntimeError, TypeError, NameError):
        print "Unable to open private key: "+key_name
        sys.exit()
    return final_key

# This function decrypts the encrypted data given in the cipher text file to the output plaintext file.
def decryption(destination_private_key_filename, sender_public_key_filename, ciphertext_file, output_plaintext_file):
    # Get the Keys
    private_key = load_private_key(destination_private_key_filename)
    public_key = load_public_key(sender_public_key_filename)
    try:
        encrypted_text = open(ciphertext_file, 'r')
    except:
        print "Cannot find cipher text file: "+ciphertext_file
        sys.exit()
    output_file = open(output_plaintext_file, 'w')

    # Get encrypted data from the ciphertext file sent by sender
    msg_key_line = encrypted_text.readline()
    msg_txt_line = encrypted_text.readline()
    signature_msg_line = encrypted_text.readline()
    signature_line = encrypted_text.readline()

    # If any of the above is null or 0 throw incorrect encryption format
    if len(msg_key_line) == 0 or len(msg_txt_line) == 0 or len(signature_msg_line) == 0 or len(signature_line) == 0:
        print "Incorrect Encryption Format"
        sys.exit()

    # Decode these lines into meaningful data
    encrypted_msg_key = base64.b64decode(msg_key_line)
    ciphertext = base64.b64decode(msg_txt_line)
    signature_msg = base64.b64decode(signature_msg_line)
    signature = base64.b64decode(signature_line)

    # Verify if the signature is correct or tampered with
    verifier = public_key.verifier(
        signature,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ), hashes.SHA256()
    )
    verifier.update(signature_msg)
    try:
        verifier.verify()
    except:
        print "Invalid signature"
        sys.exit()

    # Decrypt session key using our private key
    try:
        session_key_decrypted = private_key.decrypt(
            encrypted_msg_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
    except:
        print "Decryption Failed. Cannot decrypt session key"
        sys.exit()

    # Retrieve AES key and initialization vectorCS 4740 / CS 6740: Network Security
    aes_key = session_key_decrypted[:32]
    iv = session_key_decrypted[32:]

    # Decrypt ciphertext using AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    ct = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    unpadded_data = unpadder.update(ct) + unpadder.finalize()
    output_file.write(unpadded_data  + '\n')
    print "Message Decrypted"


 # Main Method
if __name__ == "__main__":
    if(len(sys.argv) != 6) :
        print 'Usage : openssl rsa -in privkey.pem -pubout > key.pubpython fcrypt.py -e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file ' \
              '\n OR \n' \
              'Usage : python fcrypt.py -d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file'
        sys.exit()
    mode = sys.argv[1]
    if mode=="-e" or mode=="-d":
        if mode == '-e':
            encryption(sys.argv[2],sys.argv[3],sys.argv[4],sys.argv[5])
        else:
            decryption(sys.argv[2],sys.argv[3],sys.argv[4],sys.argv[5])
    else:
        print 'Usage: Please use one of the two modes. -e for encryption and -d for decryption'
        sys.exit()