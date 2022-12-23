# AES_Decryptor.py uses the key produced by the Elliptic curve to decrypt the ciphertext
# with the exception of self._initsubKeyTable (not to be mixed up with self._subKeyTable), all of the substitution tables
# are flipped versions of the AES_Encryptor substitution tables (self._initsubKeyTable is the exact same as AES_Encryptor's self._subKeyTable).

# All of the functions are simply a reversed version of the AES_Encryptor's functions.

# imports copy.deepcopy to conduct deepcopies of lists
from copy import deepcopy


class AES_Decryptor:
    def __init__(self, key, cipherText):
        self._key = []
        self._currentText = ""
        self._subTable = [
            {'00': '75', '01': 'd7', '02': 'a0', '03': '9a', '04': '12', '05': 'd5', '06': '06', '07': '68', '08': '13',
             '09': 'de', '0a': '8e', '0b': '86', '0c': '9b', '0d': '3e', '0e': '7e', '0f': '89'},
            {'10': '50', '11': '3c', '12': '82', '13': '62', '14': '07', '15': '04', '16': '4a', '17': 'f8', '18': 'e3',
             '19': '79', '1a': '1e', '1b': '48', '1c': '36', '1d': '31', '1e': 'c1', '1f': '71'},
            {'20': '4d', '21': 'aa', '22': 'ef', '23': '5c', '24': '26', '25': '1b', '26': '97', '27': 'c6', '28': '03',
             '29': '54', '2a': 'eb', '2b': 'bb', '2c': '5f', '2d': 'e0', '2e': 'ab', '2f': '25'},
            {'30': '9f', '31': '23', '32': '41', '33': '1f', '34': '37', '35': 'a8', '36': '21', '37': '7c', '38': '18',
             '39': '00', '3a': 'e2', '3b': 'bd', '3c': 'ed', '3d': '8a', '3e': 'c4', '3f': '64'},
            {'40': '1a', '41': 'a7', '42': '87', '43': 'f4', '44': '93', '45': 'f7', '46': 'bf', '47': '72', '48': 'b1',
             '49': '78', '4a': '24', '4b': '38', '4c': 'ec', '4d': '3d', '4e': '5a', '4f': 'fc'},
            {'50': 'b3', '51': '8f', '52': 'fb', '53': 'd6', '54': 'da', '55': 'e7', '56': '49', '57': '6e', '58': 'ff',
             '59': '0b', '5a': '05', '5b': '51', '5c': '8d', '5d': 'c2', '5e': 'b0', '5f': 'b9'},
            {'60': '1c', '61': '85', '62': '20', '63': '55', '64': '0f', '65': '81', '66': '19', '67': '9e', '68': 'a1',
             '69': 'd9', '6a': '4e', '6b': '09', '6c': '08', '6d': 'b7', '6e': '52', '6f': 'c7'},
            {'70': '9c', '71': 'a2', '72': 'be', '73': 'd3', '74': '74', '75': '3b', '76': '91', '77': 'db', '78': 'a9',
             '79': '3f', '7a': 'bc', '7b': 'd2', '7c': 'e5', '7d': '7d', '7e': '2f', '7f': '2a'},
            {'80': 'a3', '81': '98', '82': 'd1', '83': '5d', '84': '7a', '85': 'ae', '86': 'd4', '87': '92', '88': '4c',
             '89': 'd8', '8a': '28', '8b': 'dd', '8c': '76', '8d': '0d', '8e': 'ea', '8f': '80'},
            {'90': 'a6', '91': 'cd', '92': '2b', '93': '77', '94': 'f0', '95': 'f2', '96': '7f', '97': '46', '98': '43',
             '99': '95', '9a': '34', '9b': '17', '9c': '4f', '9d': '84', '9e': '69', '9f': 'ce'},
            {'a0': '56', 'a1': 'c0', 'a2': 'e1', 'a3': '10', 'a4': 'e4', 'a5': '3a', 'a6': '96', 'a7': 'b4', 'a8': 'df',
             'a9': 'c9', 'aa': 'a5', 'ab': '5b', 'ac': '6b', 'ad': '6f', 'ae': '27', 'af': 'cb'},
            {'b0': '61', 'b1': '59', 'b2': '8c', 'b3': '44', 'b4': '40', 'b5': 'b6', 'b6': 'ca', 'b7': '0c', 'b8': 'f5',
             'b9': 'cf', 'ba': 'ad', 'bb': '15', 'bc': 'dc', 'bd': '42', 'be': '35', 'bf': '7b'},
            {'c0': '1d', 'c1': 'ba', 'c2': 'c3', 'c3': '9d', 'c4': '94', 'c5': '01', 'c6': 'd0', 'c7': 'e9', 'c8': '66',
             'c9': '6c', 'ca': '67', 'cb': 'a4', 'cc': 'f3', 'cd': 'c8', 'ce': '2d', 'cf': '6d'},
            {'d0': '2e', 'd1': '88', 'd2': '33', 'd3': '16', 'd4': '83', 'd5': 'f6', 'd6': '0e', 'd7': '14', 'd8': '6a',
             'd9': '47', 'da': 'c5', 'db': '57', 'dc': 'fd', 'dd': '53', 'de': 'b8', 'df': 'b5'},
            {'e0': '39', 'e1': '60', 'e2': '22', 'e3': 'e6', 'e4': '0a', 'e5': 'fe', 'e6': '02', 'e7': '63', 'e8': '90',
             'e9': 'cc', 'ea': 'ac', 'eb': 'ee', 'ec': '45', 'ed': 'e8', 'ee': '30', 'ef': '29'},
            {'f0': '11', 'f1': '8b', 'f2': 'f9', 'f3': '99', 'f4': 'f1', 'f5': 'fa', 'f6': '4b', 'f7': '70', 'f8': '58',
             'f9': '65', 'fa': '2c', 'fb': '73', 'fc': 'b2', 'fd': '32', 'fe': 'af', 'ff': '5e'}]
        self._subColTable = {3: 0, 2: 3, 0: 1, 1: 2}
        self._subKeyTable = {14: 0, 2: 1, 15: 2, 10: 3, 4: 4, 5: 5, 7: 6, 11: 7, 9: 8, 3: 9, 13: 10, 8: 11, 12: 12,
                             0: 13, 6: 14, 1: 15}
        self._initsubKeyTable = {0: 14, 1: 2, 2: 15, 3: 10, 4: 4, 5: 5, 6: 7, 7: 11, 8: 9, 9: 3, 10: 13, 11: 8, 12: 12,
                                 13: 0, 14: 6, 15: 1}
        self._ciphertext = []
        cipherRow = []
        cipherMatrix = []
        for i in range(0, len(cipherText[1]), 2):
            cipherRow.append(cipherText[1][i] + cipherText[1][i + 1])
            if (i + 2) % 8 == 0 and i != 0:
                cipherMatrix.append(cipherRow)
                cipherRow = []
            if (i + 2) % 32 == 0 and i != 0:
                self._ciphertext.append(cipherMatrix)
                cipherMatrix = []
        # flipped the values in the previous dictionaries
        self._translateKey(key)
        self._plaintext = ""

    # Takes the key, adds the x and y values together, converts the integer into bits, and puts them into 128 bit pieces
    # ***REQUIRES A KEY WHICH IS AT LEAST 128 BITS!***
    def _translateKey(self, key):
        z = ""
        x, y = key
        binary = '{0:b}'.format(int(str(x) + str(y), 16))
        binary = binary[2:]
        while len(binary) > 128:
            z += binary[:128]
            binary = binary[128:]
            self._key.append((z))
            z = ""

    #***IF YOU ADJUST "t", MAKE SURE THAT YOU ADJUST IT FOR BOTH THE ENCRYPTION AND DECRYPTION BOTH "t" VALUES MUST BE THE SAME!***
    def decrypt(self, t=20000):
        matrixRow = []
        value = ""
        plaintext = ""
        for nk in range(t):
            self._newRoundKey()
        for j in range(t):
            self._AddRoundKey()
            self._MixColumns()
            self._ShiftRows()
            self._SubBytes()
        self._oldRoundKey()
        self._removePadding()
        return self._ciphertext

    #The final stage of the key in the encryption process is recreated by running the same number of iterations
    #of the same code that was used to adjust the key during the encryption process.
    def _newRoundKey(self):
        newkey = []
        onetwoeightbitlist = []
        eightbit = ""
        onetwoeightbit = ""
        for i in self._key:
            for j in i:
                eightbit += j
                if len(eightbit) == 8:
                    newbit = int(eightbit[0]) ^ int(eightbit[2]) ^ int(eightbit[5]) ^ int(eightbit[6])
                    eightbit = eightbit[1:] + str(newbit)
                    onetwoeightbitlist.append(eightbit)
                    eightbit = ""
            for keymix in range(16):
                onetwoeightbit += onetwoeightbitlist[self._initsubKeyTable[keymix]]
            onetwoeightbitlist = []
            newkey.append(onetwoeightbit)
            onetwoeightbit = ""
        self._key = newkey


    #Once the decryption process has finished, the padding which had been aded at the beginning will be removed by _removePadding.
    #It looks at the value at the beginning of the ciphertext. If the value is a possible padding value, Then, it will see if there is that number of padding attached.
    #If there is, it will remove that padding.
    def _removePadding(self):
        hexvalues = ""
        plaintext = ""
        for i in self._ciphertext:
            for j in i:
                for s in j:
                    hexvalues += s
                    hexvalue = str(s)
                    value = chr(int(hexvalue, 16))
                    plaintext += value
        padding = hexvalues[:2]
        test = hexvalues
        testPlaintext = plaintext
        if padding[0] == "0":
            for i in range(int(padding, 16)):
                if i % 2 == 0:
                    if test[:2] == padding:
                        test = test[2:]
                    else:
                        self._ciphertext = testPlaintext
                        return
                    testPlaintext = testPlaintext[1:]
                else:
                    if test[len(test) - 2:] == padding:
                        test = test[:len(test) - 2]
                        testPlaintext = testPlaintext[:len(testPlaintext) - 1]
                    else:
                        pass
        self._ciphertext = testPlaintext

    #Uses the reversed _SubBytes function to reverse the encryption's swap
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

    #Reverses the encryptor's _ShiftRows operation
    def _ShiftRows(self):
        cipher = []

        def slide(row):
            row.reverse()
            tmp = row.pop(0)
            row.append(tmp)
            row.reverse()
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

    #Reverses the encryption's _MixColumns operation
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

    #Reverses the encryption's _AddRoundKey operation
    def _AddRoundKey(self):
        self._oldRoundKey()
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
                    val = hex(int(val, 16) ^ int(itemkey, 2))[2:]
                    if len(val) == 1:
                        val = "0" + val
                    matrixrow.append(val)
                mat.append(matrixrow)
                matrixrow = []
            cipher.append(mat)
            mat = []
        self._ciphertext = cipher

    #Reverts the key to one state closer to the original state
    def _oldRoundKey(self):
        oldkey = []
        onetwoeightbitlist = []
        eightbit = ""
        onetwoeightbit = ""
        for i in self._key:
            for j in i:
                eightbit += j
                if len(eightbit) == 8:
                    test = int(eightbit[1]) ^ int(eightbit[4]) ^ int(eightbit[5])
                    if test == 1 and test == int(eightbit[7]):
                        oldbit = 0
                    elif test == 0 and test == int(eightbit[7]):
                        oldbit = 0
                    else:
                        oldbit = 1
                    replace = str(oldbit) + eightbit[:7]
                    onetwoeightbitlist.append(replace)
                    eightbit = ""
            for keymix in range(16):
                onetwoeightbit += onetwoeightbitlist[self._subKeyTable[keymix]]
            onetwoeightbitlist = []
            oldkey.append(onetwoeightbit)
            onetwoeightbit = ""
        self._key = oldkey

