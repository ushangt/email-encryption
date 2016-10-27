# Email Encryption in Python

Assumptions:
cyptography library is installed
Keys used are pem keys

The python script to run is fcrypt.py

The commands to be used are:

- Encryption:

`python fcrypt.py -e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file`

- Decryption:

`python fcrypt.py -d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file`

Example cases used for testing by me includes:

Case 1: Proper Decryption : Works fine
Output: Message Encrypted
	    Message Decrypted

`python fcrypt.py -e destination_public.pub sender_private.pem input_text output_text`

`python fcrypt.py -d destination_private.pem sender_public.pub output_text decrypted_text`


Case 2: Different private key used to sign then the public key used for decrypting : Output: Invalid Signature

`python fcrypt.py -e destination_public.pub sender_private.pem input_text output_text`

`python fcrypt.py -d destination_private.pem sender2_public.pub output_text decrypted_text`


Case 3: Encrypted output file tampered in between sender and receiver:
Output: Decryption Failed. Cannot decrypt session key

`python fcrypt.py -e destination_public.pub sender_private.pem input_text output_text`

`python fcrypt.py -d destination_private.pem sender2_public.pub output_text_tempered decrypted_text`


Case 4: Session ID or IV changed in between sender and receiver:
Output: Incorrect Encryption Format

`python fcrypt.py -e destination_public.pub sender_private.pem input_text output_text`

`python fcrypt.py -d destination_private.pem sender2_public.pub output_text_tempered decrypted_text`


Case 5: Testing with different Size Key. Key size 1024
Output: Message Encryted
	    Message Decrypted

`python fcrypt.py -e 1024public_key.pub sender_private.pem input_text output_text`

`python fcrypt.py -d 1024private_key.pem sender_public.pub output_text decrypted_text`
