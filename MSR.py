# MSR.py is taken from Dr. Coleman's (Franciscan University Professor) supplied files

#All aspects provided by Dr. Coleman (Franciscan University professor) are used in this project with his permission.

import random


# The following function finds s and d in
# n-1 = 2^s*d with d odd
def findSD(n):
    s = 0
    d = n - 1
    while d % 2 == 0:
        s = s + 1
        d = d // 2
    return s, d


def checkBase(a, n):
    s, d = findSD(n)
    x = pow(a, d, n)
    if x == 1 or x == n - 1:
        return "probable prime"
    else:
        for i in range(s - 1):
            x = pow(x, 2, n)
            if x == 1:
                return "composite"
            elif x == n - 1:
                return "probable prime"
        # if you get to this stage, -1 not reached despite s-1
        # squarings -- so must be composite
        return "composite"


def MSR(n, k):
    # Implements the Miller-Selfridge-Rabin test for primality
    for i in range(k):
        a = random.randint(2, n - 2)
        if checkBase(a, n) == "composite":
            return "composite"
    # if you get here n has survived k potential witnesses, so
    return "probable prime"


# The following functions find a prime in the range [1,n]:

def prime(n):
    smallPrimes = [2, 3, 5, 7, 11, 13, 17, 19]

    for p in smallPrimes:
        if n == p:
            return True
        elif n % p == 0:
            return False

    if MSR(n, 20) == "composite":
        return False
    else:
        return True

def largestPrime(maxN):
    if (maxN % 2) == 0:
        maxN -= 1
    while True:
        if prime(maxN):
            return maxN
        maxN -= 2


def findPrime(maxN):
    while True:
        m = random.randint(1, maxN // 2)
        n = 2 * m + 1
        if prime(n):
            return n



