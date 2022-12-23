#AES_Encryptor.py uses the key produced by the Elliptic curve to encrypt message
#all of the substitution tables were produced by doing a large number of iterations of Pythons random.shuffle function
#to produce a more cryptographically safe encryptor, use a pseudorandom number generator to produce the lists

# The encryptor requires that the number of characters to be encrypted is a multiple of 16.
#This is becuase the encrytor changes the plaintext into 4x4 matrices with operations done on each indivicual matrix.
# This is achieved by adding padding to the ends of the plaintext prior to encrypting it so that it is a multiple of 16.

#imports copy.deepcopy to conduct deepcopies of lists
from copy import deepcopy
class AES_Encryptor:
    def __init__(self, key, originalText: str):
        self._key = []

        #used random.shuffle on the original list a large amount of times
        self._subTable = [{'00': '39', '01': 'c5', '02': 'e6', '03': '28', '04': '15', '05': '5a', '06': '06', '07': '14', '08': '6c', '09': '6b', '0a': 'e4', '0b': '59', '0c': 'b7', '0d': '8d', '0e': 'd6', '0f': '64'}, {'10': 'a3', '11': 'f0', '12': '04', '13': '08', '14': 'd7', '15': 'bb', '16': 'd3', '17': '9b', '18': '38', '19': '66', '1a': '40', '1b': '25', '1c': '60', '1d': 'c0', '1e': '1a', '1f': '33'}, {'20': '62', '21': '36', '22': 'e2', '23': '31', '24': '4a', '25': '2f', '26': '24', '27': 'ae', '28': '8a', '29': 'ef', '2a': '7f', '2b': '92', '2c': 'fa', '2d': 'ce', '2e': 'd0', '2f': '7e'}, {'30': 'ee', '31': '1d', '32': 'fd', '33': 'd2', '34': '9a', '35': 'be', '36': '1c', '37': '34', '38': '4b', '39': 'e0', '3a': 'a5', '3b': '75', '3c': '11', '3d': '4d', '3e': '0d', '3f': '79'}, {'40': 'b4', '41': '32', '42': 'bd', '43': '98', '44': 'b3', '45': 'ec', '46': '97', '47': 'd9', '48': '1b', '49': '56', '4a': '16', '4b': 'f6', '4c': '88', '4d': '20', '4e': '6a', '4f': '9c'}, {'50': '10', '51': '5b', '52': '6e', '53': 'dd', '54': '29', '55': '63', '56': 'a0', '57': 'db', '58': 'f8', '59': 'b1', '5a': '4e', '5b': 'ab', '5c': '23', '5d': '83', '5e': 'ff', '5f': '2c'}, {'60': 'e1', '61': 'b0', '62': '13', '63': 'e7', '64': '3f', '65': 'f9', '66': 'c8', '67': 'ca', '68': '07', '69': '9e', '6a': 'd8', '6b': 'ac', '6c': 'c9', '6d': 'cf', '6e': '57', '6f': 'ad'}, {'70': 'f7', '71': '1f', '72': '47', '73': 'fb', '74': '74', '75': '00', '76': '8c', '77': '93', '78': '49', '79': '19', '7a': '84', '7b': 'bf', '7c': '37', '7d': '7d', '7e': '0e', '7f': '96'}, {'80': '8f', '81': '65', '82': '12', '83': 'd4', '84': '9d', '85': '61', '86': '0b', '87': '42', '88': 'd1', '89': '0f', '8a': '3d', '8b': 'f1', '8c': 'b2', '8d': '5c', '8e': '0a', '8f': '51'}, {'90': 'e8', '91': '76', '92': '87', '93': '44', '94': 'c4', '95': '99', '96': 'a6', '97': '26', '98': '81', '99': 'f3', '9a': '03', '9b': '0c', '9c': '70', '9d': 'c3', '9e': '67', '9f': '30'}, {'a0': '02', 'a1': '68', 'a2': '71', 'a3': '80', 'a4': 'cb', 'a5': 'aa', 'a6': '90', 'a7': '41', 'a8': '35', 'a9': '78', 'aa': '21', 'ab': '2e', 'ac': 'ea', 'ad': 'ba', 'ae': '85', 'af': 'fe'}, {'b0': '5e', 'b1': '48', 'b2': 'fc', 'b3': '50', 'b4': 'a7', 'b5': 'df', 'b6': 'b5', 'b7': '6d', 'b8': 'de', 'b9': '5f', 'ba': 'c1', 'bb': '2b', 'bc': '7a', 'bd': '3b', 'be': '72', 'bf': '46'}, {'c0': 'a1', 'c1': '1e', 'c2': '5d', 'c3': 'c2', 'c4': '3e', 'c5': 'da', 'c6': '27', 'c7': '6f', 'c8': 'cd', 'c9': 'a9', 'ca': 'b6', 'cb': 'af', 'cc': 'e9', 'cd': '91', 'ce': '9f', 'cf': 'b9'}, {'d0': 'c6', 'd1': '82', 'd2': '7b', 'd3': '73', 'd4': '86', 'd5': '05', 'd6': '53', 'd7': '01', 'd8': '89', 'd9': '69', 'da': '54', 'db': '77', 'dc': 'bc', 'dd': '8b', 'de': '09', 'df': 'a8'}, {'e0': '2d', 'e1': 'a2', 'e2': '3a', 'e3': '18', 'e4': 'a4', 'e5': '7c', 'e6': 'e3', 'e7': '55', 'e8': 'ed', 'e9': 'c7', 'ea': '8e', 'eb': '2a', 'ec': '4c', 'ed': '3c', 'ee': 'eb', 'ef': '22'}, {'f0': '94', 'f1': 'f4', 'f2': '95', 'f3': 'cc', 'f4': '43', 'f5': 'b8', 'f6': 'd5', 'f7': '45', 'f8': '17', 'f9': 'f2', 'fa': 'f5', 'fb': '52', 'fc': '4f', 'fd': 'dc', 'fe': 'e5', 'ff': '58'}]
        self._subColTable = {0:3, 3:2, 1:0, 2:1}
        self._subKeyTable = {0: 14, 1: 2, 2: 15, 3: 10, 4: 4, 5: 5, 6: 7, 7: 11, 8: 9, 9: 3, 10: 13, 11: 8, 12: 12, 13: 0, 14: 6, 15: 1}

        #The large number of spaces in the Plaintext could potentially be used to crack the cipher.
        #While it would be less readable, remove the comments in the two lines below to get rid of upper case letters and spaces.
#        originalText = originalText.replace(" ", "")
#        originalText = originalText.lower()

        self._translateKey(key)
        self._plaintext = ""
        self._translatePlaintext(originalText)
        self._addPadding()
        self._ciphertext = []

    #Takes the key, adds the x and y values together, converts the integer into bits, and puts them into 128 bit pieces
    #***REQUIRES A KEY WHICH IS AT LEAST 128 BITS!***
    def _translateKey(self, key):
        z = ""
        x, y = key
        binary = '{0:b}'.format(int(str(x)+str(y),16))
        binary = binary[2:]
        while len(binary) > 127:
            z += binary[:128]
            binary = binary[128:]
            self._key.append((z))
            z = ""

    #Changes the plaintext into their unicode byte value to get ready for the encryption
    def _translatePlaintext(self, plaintext):
        for i in plaintext:
            h = hex(ord(i))
            self._plaintext += h[2:]
            z = 0

    #The _addPadding function ensures that the number of characters in the plaintext will be a multiple of 16.
    def _addPadding(self):
        remainder = (len(self._plaintext))%32
        if remainder != 0:
            if remainder % 2 != 0:
                padding = "0" + hex((32 - remainder) // 2)[2:]
            else:
                padding = "0" + hex((32 - remainder) // 2)[2:]
            for i in range((32 - remainder)//2):
                if i % 2 == 0:
                    self._plaintext = padding + self._plaintext
                else:
                    self._plaintext = self._plaintext + padding

    #The encrypt function arranges the plaintext's hexadecimal values into a list of 4x4 matrices with one byte per cell.
    #Then, it conducts the encryption by calling the AES operations t times (t is initially set to 20000, but can be changed).
    #Finally, it takes the encrypted matrix and returns the ciphertext as both a hexidecimal string and a character string using the Unicode values.
    #***IF YOU ADJUST "t", MAKE SURE THAT YOU ADJUST IT FOR BOTH THE ENCRYPTION AND DECRYPTION BOTH "t" VALUES MUST BE THE SAME!***
    def encrypt(self, t = 20000):
        matrixRow = []
        matrix = []
        value = ""
        ciphertext = ""
        hextext = ""
        length = len(self._plaintext)
        for i in range(0,length,2):
            if (i) % 8 == 0 and i != 0:
                matrix.append(matrixRow)
                matrixRow = []
            if (i) % 32 == 0 and i != 0:
                if matrixRow != []:
                    matrix.append(matrixRow)
                self._ciphertext.append(matrix)
                matrix = []
            value += self._plaintext[i] + self._plaintext[i+1]
            matrixRow.append(value)
            value = ""
        if matrixRow != []:
            matrix.append(matrixRow)
        if matrix != []:
            self._ciphertext.append(matrix)
        if self._ciphertext == []:
            if matrixRow != []:
                matrix.append(matrixRow)
            self._ciphertext.append(matrix)
        for j in range(t):
            self._SubBytes()
            self._ShiftRows()
            self._MixColumns()
            self._AddRoundKey()
        for i in self._ciphertext:
            for j in i:
                for s in j:
                    hextext += s
                    ciphertext += chr(int(s,16))
        return ciphertext, hextext

    #The _SubBytes function simply uses the subTable to replace each byte with a new one.
    def _SubBytes(self):
        matrixRow = []
        matrix = []
        tmpCipher = []
        tmpString = ""
        for i in self._ciphertext:
            for j in i:
                for s in j:
                    if s[0] == 'a':
                        dict = self._subTable[10]
                        tmpString += dict[s]
                    elif s[0] == 'b':
                        dict = self._subTable[11]
                        tmpString += dict[s]
                    elif s[0] == 'c':
                        dict = self._subTable[12]
                        tmpString += dict[s]
                    elif s[0] == 'd':
                        dict = self._subTable[13]
                        tmpString += dict[s]
                    elif s[0] == 'e':
                        dict = self._subTable[14]
                        tmpString += dict[s]
                    elif s[0] == 'f':
                        dict = self._subTable[15]
                        tmpString += dict[s]
                    else:
                        dict = self._subTable[int(s[0])]
                        tmpString += dict[s]
                    matrixRow.append(tmpString)
                    tmpString = ""
                matrix.append(matrixRow)
                matrixRow = []
            tmpCipher.append(matrix)
            matrix = []
        self._ciphertext = tmpCipher

    #The _ShiftRows function moves the bytes around the matrix.
    def _ShiftRows(self):
        cipher = []
        def slide(row):
            tmp = row.pop(0)
            row.append(tmp)
            return row
        for i in self._ciphertext:
            tmp = []
            for j in range(len(i)):
                row = i.pop(0)
                if j == 0:
                    tmp.append(row)
                else:
                    for n in range(j):
                        newRow = slide(row)
                    tmp.append(newRow)
            cipher.append(tmp)
        self._ciphertext = cipher

    #The _MixColumns function swaps columns around using the subColTable.
    def _MixColumns(self):
        cipher = []
        output = []
        tmp = []
        for i in self._ciphertext:
            for r in range(len(i)):
                for c in range(len(i[r])):
                    newcol = self._subColTable[c]
                    tmp.append(i[r][newcol])
                cipher.append(deepcopy(tmp))
                tmp = []
            output.append(cipher)
            cipher = []
        self._ciphertext = output

    #The _AddRoundKey function uses the shared secret key to adjust the individual bits of the plaintext character values.
    #It then calls the _newRoundKey function to change up the key before the next iteration.
    def _AddRoundKey(self):
        mat = []
        matrixrow = []
        cipher = []
        for i in range(len(self._ciphertext)):
            matrix = self._ciphertext[i]
            for j in range(len(matrix)):
                row = matrix[j]
                for s in range(len(row)):
                    val = row[s]
                    beginning = (j + 1) * (s + 1)
                    itemnum = i % len(self._key)
                    itemkey = self._key[itemnum][(beginning - 1):(beginning + 7)]
                    val = hex(int(val,16) ^ int(itemkey,2))[2:]
                    if len(val) == 1:
                        val = "0" + val
                    matrixrow.append(val)
                mat.append(matrixrow)
                matrixrow = []
            cipher.append(mat)
            mat = []
        self._ciphertext = cipher
        self._newRoundKey()

    #The _newRoundKey function takes each set of 128 bits in the key.
    #Each set of 128 bits is divided into 8 bit pieces. These pieces go through a Linear Feedback Shift Register to adjust their bits.
    #Then, the sets of 8 bits are shuffled around in a determined manner using the subKeyTable.
    #This process is done per set of 128 bits in the key.
    def _newRoundKey(self):
        newkey = []
        onetwoeightbitlist = []
        eightbit = ""
        onetwoeightbit = ""
        for i in self._key:
            for j in i:
                eightbit += j
                if len(eightbit) == 8:
                    newbit = int(eightbit[0])^int(eightbit[2])^int(eightbit[5])^int(eightbit[6])
                    eightbit = eightbit[1:] + str(newbit)
                    onetwoeightbitlist.append(eightbit)
                    eightbit = ""
            for keymix in range(16):
                onetwoeightbit += onetwoeightbitlist[self._subKeyTable[keymix]]
            onetwoeightbitlist = []
            newkey.append(onetwoeightbit)
            onetwoeightbit = ""
        self._key = newkey