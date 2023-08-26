# Koder-AES-Encryption

NOTE: KreativeKoder032 and KoehlerKode are two separate accounts for the same user. KoehlerKode is a school account while KreativeKoder032 is a personal account.

This is a simple implementation of an AES Encryption using a shared key that is created with two Elliptic points on Bitcoin's secp256k1 elliptic curve.
Some of the files used aspects that were given by a Franciscan University professor, Dr. Coleman, for homework assignments. These aspects are used with his permission and have been noted in the files that used them.
  
I used JetBrains' PyCharm IDE to create this project and have since deleted all of the extra files associated with the IDE to leave just core Python files.
  See PyCharm help at https://www.jetbrains.com/help/pycharm/

To see an example implementation of the project, look at the main.py file. All six files are required for the main file to run.
If you want to use a different elliptic curve than the default, note that the key (the x value of the shared secret added to the y value) has to be at least 128 bits long.

The AES_Encryptor uses the key to encrypt a message.
It performs multiple iterations of a series of operations.
The four operations are: byte substitution, row shift, column swap, and bit flipping using the key.
In byte substitution, all of the bytes are substituted in a predetermined manner.

In row shifting, each row of the 4x4 matrix has its values slide down (n - 1) times where n is the number of the row in question. All values that go off one end are placed back on the other end.
  
In column swap, each of the 4x4 matrix's columns are shuffled in a predetermined manner.

In the bit flipping, each 4x4 matrix uses the (i % len(key)) subkey where i is the number of the matrix being used and len(key) is the number of 128 bit subkeys that are present in the key. Once the subkey has been determined, it is split into 8 bit pieces. Each of these pieces is XORed with 8 bits in the cells of the 4x4 matrix. After this is done for all of the message, the key itself is adjusted. Each 128 bit subkey is split into 8 bit pieces. Then, the 8 bit pieces go through a linear feedback shift register. Finally, they are shuffled in a determined manner and stored back into the key as a 128 bit subkey.
  
This process is repeated t times where t is 20000 times by default, but can be adjusted by the user via the t parameter.

The AES_Decryptor uses the determined nature of the different aspects of the encryption that involve shuffling and swapping to undo each of the operations.
  So that I am not overly repetative, I will not restate what is said above concerning the operations. The decryptor symply reverses the encryptor's operations. 
  One thing to note is that the value of t is also 20000 for the decryptor. If you adjust one, you will have to adjust the other.
