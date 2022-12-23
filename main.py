#main.py is the file that runs the other files

#All aspects provided by Dr. Coleman (Franciscan University professor) are used in this project with his permission.

#Imports the other files that are included in the branch
from Elliptic_Point import Elliptic_Point
from Elliptic_Curve import Elliptic_Curve
from AES_Encryptor import AES_Encryptor
from AES_Decryptor import AES_Decryptor


#Bob and Alice are two hypothetical people who are attempting to communicate with encrypted messages.
#The encryption will use the default elliptic curve (Bitcoin's secp256k1)
#https://en.bitcoin.it/wiki/Secp256k1

#Each will create a point and announce it (their public key). Then, each will use the other person's point to find a shared secret key.
#Bob will use this shared secret key to encrypt a message. Finally, Alice will use the encrypted message and the shared secret key to produce the original message.

def main():
    curve = Elliptic_Curve()
    print(curve)
    BobPoint = Elliptic_Point(curve,9860721)
    print("Bob's point is: {0}.".format(BobPoint))
    AlicePoint = Elliptic_Point(curve, 2813709)
    BobSharedSecretKey = BobPoint.keyGenerator(AlicePoint)
    print("Alice's point is: {0}.".format(AlicePoint))
    print("The Shared Secret which Bob has is: {0}".format((BobSharedSecretKey)))
    BobPlainText = '"It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of foolishness, it was the epoch of belief, it was the epoch of incredulity, it was the season of light, it was the season of darkness, it was the spring of hope, it was the winter of despair." -A Tale of Two Cities by Charles Dickens'
    BobEncryptor = AES_Encryptor(BobSharedSecretKey,BobPlainText)
    BobCipherText = BobEncryptor.encrypt()
    print("Bob's Ciphertext is:")
    print("{0}".format(BobCipherText[0]))
    AliceSharedSecretKey = AlicePoint.keyGenerator(BobPoint)
    print("The Shared Secret which Alice has is: {0}".format((AliceSharedSecretKey)))
    AliceDecryptor = AES_Decryptor(AliceSharedSecretKey,BobCipherText)
    AlicePlainText = AliceDecryptor.decrypt()
    print("Alice's PlainText is: {0}".format(AlicePlainText))

if __name__ == '__main__':
    main()

