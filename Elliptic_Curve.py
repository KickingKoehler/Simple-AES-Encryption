# Elliptic_Curve.py contains the Elliptic_Curve class

# All aspects provided by Dr. Coleman (Franciscan University professor) are used in this project with his permission.

# This class uses Bitcoin's secp256k1 Elliptic curve as its default elliptic curve
# https://en.bitcoin.it/wiki/Secp256k1


# Uses MSR to find the order of the p value
# If the value of n is not given, the initializer will find the value of the order of the curve.
# However, this will take some time since it will have to go through all the points first.
import MSR


class Elliptic_Curve():
    def __init__(self, p="0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", a="0x0", b="0x7",
                 G=("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
                    "0x1b888e01a06e974017a28a5b4da436169761c9730b7aeedf75fc60f687b46e0d23ccac802a2b57f02069045e7a4d24845dc2385f475b6a5636c55ea9097aaf277dba023b6a09dc147de1923d87eb2ecb662f7b3392bd2744a2fff1a671ee10037f76455dd97ea53f79892c6900467c9b7fb7a760994c7758ce1f7b2a682d111020b6c29765fd66d6e29528723a65a51dc8d916c30822dd08d08eaf530adc008749966a7aa28e7009b2f8026ab03425329a8b593600cc957fc112b81c236e0e07"),
                 n="0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", h="0x1"):
        if type(p) == tuple:
            for i in range(5):
                if i == 0:
                    self._p = p[i]
                elif i == 1:
                    self._a = p[i]
                elif i == 2:
                    self._b = p[i]
                elif i == 3:
                    self._G = p[i]
                elif i == 4:
                    if n == 0:
                        self._n = self.getOrder()
                    else:
                        self._n = n
                else:
                    self._h = p[i]


        else:
            if type(p) != int:
                self._p = int(str(p), 16)
            else:
                self._p = p
            if type(a) != int:
                self._a = int(str(a), 16)
            else:
                self._a = a
            if type(b) != int:
                self._b = int(str(b), 16)
            else:
                self._b = b
            c, d = G
            if type(c) != int:
                intc = int(str(c), 16)
            else:
                intc = c
            if type(d) != int:
                intd = int(str(d), 16)
            else:
                intd = d
            self._G = (intc, intd)
            if type(n) != int:
                if n == 0:
                    self._n = self.getOrder()
                else:
                    self._n = n
            else:
                self._n = n
            if type(h) != int:
                self._h = int(str(h), 16)
            else:
                self._h = h

    def getInitialPoint(self):
        return self._G

    # returns the aspects of the curve as a tuple
    def returnCurve(self):
        return self._p, self._a, self._b, self._G, self._n, self._h

    # used the findCurve Algorithm that was provided by Dr. Coleman (Franciscan University Professor)
    # This function pulls all the points from the curve up to the value of self._p
    def findCurve(self):
        # finds all points (x,y) in Z_p x Z_P
        # with y^3 = x^2+ax+b (mod p)
        # uses shortcut under assumption
        # that p is an odd prime

        # first make a dictionary of square roots
        squareRoots = {}  # empty dictionary to hold square roots
        for y in range((self._p + 1) // 2):
            squareRoots[pow(y, 2, self._p)] = y

        points = []
        for x in range(self._p):
            RHS = (pow(x, 3, self._p) + self._a * x % self._p + self._b) % self._p
            if RHS in squareRoots:
                y = squareRoots[RHS]
                if y == 0:
                    points.append((x, y))
                else:
                    points.extend([(x, y), (x, self._p - y)])
        return points

    # uses MSR to find the order of the elliptic curve; because it also uses the findCurve function, this process
    # will take some time when using an elliptic curve with larger values
    def getOrder(self):
        points = self.findCurve()
        maxVal = len(points) + 1
        return MSR.largestPrime(maxVal)

    # returns the function of the elliptic curve, the starting point, the value of p, the order of the elliptic
    # curve, and the value of h in string form
    def __str__(self) -> str:
        return f"Function: y = x^3 + {self._a}*x + {self._b}\nStarting Point: {self._G}\nValue of p: {self._p}\nValue of n: {self._n}\nValue of h: {self._h}"
