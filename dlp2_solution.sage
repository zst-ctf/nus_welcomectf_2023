#!/usr/local/bin/python
from secrets import randbits
from hashlib import shake_256

# Submit to oracle
p = 13235062921662694429211184891220141973285969028958016790661658609292023032453887458389574420664371217218833375173082540739555090686687826551693380798574629365254210787419070348340076227508521415632755789594367616391764583712987637766374230688082101873347891400341145784790200266806419168972691757367828474132879
g = 2

if False:
    # Test case
    FLAG = b'REDACTED'

    def checkModulus(p):
        if not p.is_prime():
            print("Your modulus is not prime!")
            exit(0)
        else:
            print("Your modulus is prime!")

    def encryptFlag(s):
        key = shake_256(str(s).encode()).digest(len(FLAG))
        return bytes([i ^^ j for i, j in zip(key, FLAG)])

    print("Let's perform Diffie–Hellman Key exchange!")
    # p = int(input("Send me your modulus: "))
    # g = int(input("Send me your base: "))

    checkModulus(p)

    secret = randbits(1024)
    A = pow(g, secret, p)
    print(f"My secret: {secret}")
    print(f"My public output: {A}")
    print(f"c: {encryptFlag(secret).hex()}")

else:
    # Retrieve from oracle
    # My public output:
    A = 8222459661639387871979740047520846551550571683657468330919820469690909208331322164107333000654600738628825927254564579980172503806655912961846807846464840324171585102307146703068622936653473297936254652609468569321603966091693245225635554027457026101656007445655120309745352816957589589186911352733176011856514
    # c:
    c = '5e05825c43e11f91792fa2ebd73beb093507ca11d53a47552086fb7b335019759867b2c9f61757ac69b6de53876fff691ff7d682bb2eb4855ee30a17c38be556f221'
    c = bytes.fromhex(c)

    def decryptFlag(s):
        key = shake_256(str(s).encode()).digest(len(c))
        return bytes([i ^^ j for i, j in zip(key, c)])


# ---------------- Decrypt flag ----------------
F = IntegerModRing(p)

secret = discrete_log(F(A), F(g))
print('secret', secret)
print(decryptFlag(secret))


