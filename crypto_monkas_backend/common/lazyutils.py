from random import randrange, getrandbits, randint
from typing import List

def is_prime(n, k=128):
    # Test if n is not even.
    # But care, 2 is prime !
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    # find r and s
    s = 0
    r = n - 1
    while r & 1 == 0:
        s += 1
        r //= 2
    # do k tests
    for _ in range(k):
        a = randrange(2, n - 1)
        x = pow(a, r, n)
        if x != 1 and x != n - 1:
            j = 1
            while j < s and x != n - 1:
                x = pow(x, 2, n)
                if x == 1:
                    return False
                j += 1
            if x != n - 1:
                return False    
    return True

def generate_prime_candidate(length):
    # generate random bits
    p = getrandbits(length)
    # apply a mask to set MSB and LSB to 1
    p |= (1 << length - 1) | 1
    return p

def generate_prime_number(length=1024):
    p = 4
    # keep generating while the primality test fail
    while not is_prime(p, 128):
        p = generate_prime_candidate(length)
    return p

def euclidExt(a : int, b : int):
    # Algoritmo extendido de euclides
    # Usado para calcular el inverso multiplicativo de a modulo b.
    # Pues por el teorema de Bezout:
    #   ax + by = (MAXIMO DIVISOR DE a Y b)
    # y si no tienen factores en comun, entonces:
    #   ax + by = 1.
    #   ax = 1 (mod b)
    r0, r1, s0, t0, s1, t1 = a, b, 1, 0, 0, 1
    while r1 != 0:
        temp1, temp2 = s1, t1
        s1 = s0 - (r0 // r1) * s1
        t1 = t0 - (r0 // r1) * t1
        s0 = temp1
        t0 = temp2
        temp = r1
        r1 = r0 % r1
        r0 = temp
    return s0, t0

def modInverse(a : int, n : int):
    # Calcula el inverso multiplicativo de a modulo n
    # Es decir:
    # modInverse(a, n) * a = 1 (mod n)
    inv, trash = euclidExt(a, n)
    while inv < 0:
        inv += n
    return inv % n

def TCR(lista, listb):
    # Teorema Chino del residuo. Si
    # lista = [a0, a1, a2, ..., an]
    # listb = [b0, b1, b2, ..., bn]
    # Donde los ai son coprimos dos a dos. Entonces
    # X = TCR(lista, listb) es la solucion al sistema de congruencias
    # x = b0 (mod a0)
    # x = b1 (mod a1)
    # ...
    # x = bn (mod an)
    m = 1
    for a in lista:
        m *= a
    M = [m // a for a in lista]
    invM = [modInverse(M[i], lista[i]) for i in range(len(M))]
    result = 0
    for i in range(len(M)):
        result += (listb[i] * M[i] * invM[i]) % m
    return result % m

def expMod(b : int, e : int, m : int):
    # Calcula b**e modulo m
    r = 1
    if 1 & e:
        r = b
    while e:
        e >>= 1
        b = (b * b) % m
        if e & 1: r = (r * b) % m
    return r

def primeFactor(n : int):
    # Halla factores primos de n
    i = 2
    factors = []
    while n > 1:
        if n % i == 0:
            factors.append(i)
            while n % i == 0:
                n = n // i
        i += 1
    return factors

def primitiveRootTest(a : int, p : int):
    # determina si todo numero en Zp puede ser escrito
    # como una potencia de a.
    fact = primeFactor(p - 1)
    for f in fact:
        if expMod(a, (p - 1) // f, p) == 1:
            return False
    return True

def encRabin(numberlist, B : int, n: int):
    # n = p*q
    # p y q son primos impares
    # p % 4 == 3, q % 4 == 3
    # B es un numero entre 0 y n - 1
    return list(map(lambda x: (x * (x + B)) % n, numberlist))

def decRabin(numberlist: List[int], B : int, p : int, q : int):
    inv2 = modInverse(2, p * q)
    inv4 = inv2 * inv2 % (p * q)
    sol = []
    for n in numberlist:
        temp = inv4 * B ** 2 + n
        powers = [expMod(temp, (p + 1) // 4, p), expMod(temp, (q + 1) // 4, q)]
        roots = [TCR([p, q], powers),
                 TCR([p, q], [powers[0], -powers[1]]),
                 TCR([p, q], [-powers[0], powers[1]]),
                 TCR([p, q], [-powers[0], -powers[1]])]
        t = []
        for r in roots:
            number = r - inv2 * B
            t.append(number % (p * q))
        sol.append(t)
    return sol

def encRSA(numberlist, a, n):
    # n = p*q.  p, q, primos
    # a es coprimo con (p-1)(q-1)
    return list(map(lambda x: expMod(x, a, n), numberlist))

def decRSA(numberlist, a, p, q):
    # p, q, primos
    # a es coprimo con (p-1)(q-1)
    b = modInverse(a, (p-1) * (q-1))
    return list(map(lambda x: expMod(x, b, p*q), numberlist))

def encGamal(numberlist, a, b, p):
    # p primo
    # a ** exp = b
    # primitiveRootTest(a, p) == True
    output = []
    for n in numberlist:
        h = randint(0, p - 1)
        output.append((expMod(a, h, p), (n * expMod(b, h, p)) % p))
    return output

def decGamal(pairlist, a, exp, p):
    # p primo
    # a ** exp = b
    # primitiveRootTest(a, p) == True
    output = []
    for pair in pairlist:
        y1, y2 = pair
        output.append((y2 * modInverse(expMod(y1, exp, p), p)) % p)
    return output