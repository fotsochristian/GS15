import random
from ressources import *
from sympy import isprime


# Calcul du pgcd par l'algorithme d'Euclide
def pgcd(a, b):
    while a % b != 0:
        a, b = b, a % b
    return b


"""
# Fonction indicatrice d'Euleur     TO DO !!!
def phi(n):
    if rabin_miller(n):
        return n-1
"""


# Identité de Bezout
def bezout(a, b):
    x0, y0, r0, x1, y1, r1 = 1, 0, a, 0, 1, b
    while r1 != 0:
        r0, (q, r1) = r1, divmod(r0, r1)
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    #line = f"{x0}x{a} + {y0}x{b} = pgcd({a},{b}) = {r0}"
    #print(line)
    # Si pgcd(a,b) = r0 = 1 alors l'inverse de a mod b est x0
    return x0, y0, r0


# Calcul de l'inverse modulaire de a modulo m
def inv(a, m):
    if pgcd(a, m) != 1:
        raise Exception("a et m ne sont pas copremiers")
    else:
        return bezout(a, m)[0] % m


# Exponentiation rapide modulaire
def expo(a, e, m):
    res = 1
    while e > 0:
        if e % 2 == 1:
            res = (res * a) % m
        e, a = e//2, (a*a) % m
    return res


# Test de Rabin-Miller
def rabin_miller(n):
    if n <= 1 or n % 2 == 0 or (n < 10000 and n not in SMALL_PRIMES):
        return False
    if n in SMALL_PRIMES:
        return True
    s, d = 0, n-1
    while d % 2 == 0:
        s += 1
        d //= 2
    is_prime = False
    for _ in range(40):
        a = random.randrange(n)
        u = expo(a, d, n)
        if u == 1:
            is_prime = True
        for r in range(s):
            if expo(u, 2**r, n) == n-1:
                is_prime = True
    return is_prime


# Génératéur de nombre premier de n bits
def prime_gen(n):
    while True:
        a = random.randrange(2**(n-2), (2**(n-1) - 1))
        b = (2 * a) + 1
        #if rabin_miller(b):
        if isprime(b):            #if isprime(b):  # de la librairie sympy par souci d'efficacité mais équivalent au test de rabin_miller()
            return b


# Génératéur de nombre premier fort de n bits
def prime_gen_strong(n):
    while True:
        a = prime_gen(n-1)
        b = (2 * a) + 1
        #if rabin_miller(b):
        if isprime(b):            #if isprime(b):  # de la librairie sympy par souci d'efficacité mais équivalent au test de rabin_miller()
            return b


# Element generateur
def gen_elmt(p):
    m = p-1
    q = (p-1)//2
    for a in range(2, p):
        if expo(a, 2, p) != 1 and expo(a, q, p) != 1 and expo(a, m, p) == 1:
            return a


# Generation des clés RSA 2048
def rsa_key_gen():
    p = prime_gen(1024)
    q = prime_gen(1024)
    if isprime(p) and isprime(q):
        n = p * q
        phi = (p-1) * (q-1)
        while True:
            e = SMALL_PRIMES[random.randrange(len(SMALL_PRIMES))]
            if pgcd(e, phi) == 1:
                d = inv(e, phi)
                rsa_pub_key = [n, e]
                rsa_priv_key = [n, d]
                return rsa_pub_key, rsa_priv_key


# Fonction de hashage 512 bits
def hash512(hash):
    mod = int('f' * 128, 16)
    hexa = ''.join(format(ord(x), '0x') for x in str(hash))
    dec = int(hexa, 16)
    while len(hexa) < 128:
        dec = expo(dec, mod/2, mod)
        hexa = str(hex(int(dec)))[2:]
    from textwrap import wrap as wp
    bina = wp(str(bin(dec))[2:], 512)
    bin_hash = '0'
    for b in bina:
        bin_hash = '{:b}'.format(int(bin_hash, 2) | int(b, 2))
        hash = hex(int(bin_hash, 2))[2:]
    return hash


# Signature RSA : Inspired by cryptobook.nakov.com/digital-signatures/ RSA: Sign / Verify - Examples
def sign_rsa(msg, rsa_priv_key):
    msg = bytes((str(msg)), 'utf-8')
    hash = int(hash512(msg), 16)
    signature = expo(hash, rsa_priv_key[1], rsa_priv_key[0])
    return signature


# Verification de signature RSA
def verif_rsa(msg, sign, rsa_pub_key):
    msg = bytes((str(msg)), 'utf-8')
    hash = int(hash512(msg), 16)
    sign_hash = expo(sign, rsa_pub_key[1], rsa_pub_key[0])
    return (hash == sign_hash)


# Definition de la Key-Derivation Function
def kdf(ChainKey, const):
    hmac = str(int(hash512(str(ChainKey)+str(const)+str(random.random())), 16))
    keylenght = len(hmac)//2
    MessageKey = int(hmac[keylenght:])
    ChainKey = int(hmac[:keylenght])
    return MessageKey, ChainKey


# Fonction de chiffrement sysmétrique vigenere
def encrypt(clair, key):
    lenght = max(len(clair), len(key))
    if len(clair) < lenght:
        key = key[:len(clair)]
    else:
        key = (key * (lenght // len(key) + 1))[:lenght]
    xor = []
    for c, k in zip(clair, key):
        xored = hex(ord(c) ^ ord(k))
        xor.append(xored)
    cipher = ''.join(xor)
    return cipher, xor


# Fonction de déchiffrement sysmétrique vigenere
def decrypt(cipher, key):
    lenght = max(len(cipher), len(key))
    if len(key) < lenght:
        key = (key * (lenght // len(key) + 1))[:lenght]
    xor = []
    for c, k in zip(cipher, key):
        xored = chr(int(c, 16) ^ ord(k))
        xor.append(xored)
    clair = ''.join(xor)
    return clair
