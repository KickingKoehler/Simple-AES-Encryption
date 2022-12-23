#Elliptic_Point.py contains the Elliptic_Point class

#All aspects provided by Dr. Coleman (Franciscan University professor) are used in this project with his permission.

#import the Elliptic_Curve Class which it inherits and uses heavily in its computations
from Elliptic_Curve import Elliptic_Curve

#Inherits the Elliptic_Curve class and adds on the point attibutes to the curve attributes
class Elliptic_Point(Elliptic_Curve):

    #initializes by default to the Secp256k1 Elliptic Curve at the first iteration
    #it uses either a point or a multiplier to initialize the point
    def __init__(self, curve = Elliptic_Curve(), k = 1, point = ()):
        curvedata = curve.returnCurve()
        super().__init__(curvedata)
        self._Curve = Elliptic_Curve(curvedata)
        self._k = k
        if point != ():
            self._point = point
        else:
            self._point = self._G
            self._point = self._multiplyPoint(k)

    #returns the point
    def getPoint(self):
        return self._point

    #This is a helper function for the _multiplyPoint function which adds two points together
    #With a few small tweaks, this was provided by Franciscan University professor Dr. Coleman for a homework assignment
    def _addTuple(self, firstPoint, secondPoint):
        if firstPoint == '0':
            return secondPoint
        elif secondPoint == '0':
            return firstPoint
        else:
            x_P, y_P = secondPoint
            x_Q, y_Q = firstPoint
            if x_P == x_Q:
                if y_Q != y_P:
                    # must be P = -Q, so
                    return 'O'
                else:
                    # must be P = Q, so
                    s = (3 * pow(x_P, 2, self._p) + self._a) % self._p  # numerator
                    s = s * pow((2 * y_P), self._p - 2, self._p) % self._p  # times inverse of denom
            else:
                # compute s in distinct points case:
                s = (y_Q - y_P) % self._p
                s = s * pow(x_Q - x_P, self._p - 2, self._p) % self._p
            x_R = (pow(s, 2, self._p) - x_P - x_Q) % self._p
            y_R = (-y_P + s * (x_P - x_R)) % self._p
            return x_R, y_R


    # used the multiply point function that was provided by Franciscan University professor Dr. Coleman for a homework assignment
    #the _multiplyPoint function multiplies the point by an integer; it is used by the initializer and by the keyGenerator
    def _multiplyPoint(self, k: int):
        D = self._point  # successive doubles
        S = '0'  # will be returned as final answer

        while k > 1:
            k, r = divmod(k, 2)
            if r == 1: S = self._addTuple(D,S)
            D = self._addTuple(D, D)
        S = self._addTuple(S, D)
        return S

    #the keyGenerator function produces the shared secret key by multiplying another point by its own k value
    def keyGenerator(self, otherPoint):
        if self.getInitialPoint() == otherPoint.getInitialPoint():
            x = otherPoint._multiplyPoint(self._k)
            return x

    #simple string producing function
    def __str__(self):
        return str(self._point)
