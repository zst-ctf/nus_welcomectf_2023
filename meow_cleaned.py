hexes = None
def myprinter(x):
    global hexes
    myxor=lambda x, y: bytes([x ^ y for x, y in zip(x, y)])
    if hexes:
       hexes = myxor(hexes, x)
    else:
        hexes = x
    print(x.hex())
    return x

(
    lambda __import__: (
        lambda cmath, hashlib, sys, sx, sy, pattern, xor, print, range, __file__: [
            (
                lambda _: (
                    lambda j: print(
                        (
                            b"\n"
                            + b"%s{%s}"
                            % (
                                xor(b"a\36\xaf\xdb\x81" b"\xa5" b"\xfe\x90", j),
                                xor(
                                    __file__.encode() * 2,
                                    b"\13q;Bdx&c\14s\30:ku<>+\x0e'\x1cq*1Cg;:r\r\x17,r%\"s",
                                ),
                            )
                        ).decode()
                    )
                    if j == b"\x06l\xca\xa2\xe9\xc4\x8a\xe3X\xf1\xe3\x00n\xa2C\x14:\x0fb\xc3"
                    else print("\x1b\08" + open(__file__).read())
                )(j.__defaults__[1][0]) # resolves to `thisfile` after it goes through f() fractal generation process.
            )(
                [
                    (
                        lambda c: print(
                            "\x1b\08"
                            + "\n".join(
                                "".join(
                                    pattern[
                                        int(
                                            (
                                                lambda x, y, c: max(
                                                    0,
                                                    min(
                                                        1,
                                                        j(
                                                            3 * x / sx
                                                            - 1.5
                                                            + (3 * y / sy - 1.5)
                                                            * sy
                                                            / sx
                                                            * 2.35j,
                                                            c,
                                                        ),
                                                    ),
                                                )
                                            )(x, y, c)
                                            * len(pattern)
                                            * 0.9
                                        )
                                    ]
                                    for x in range(sx)
                                )
                                for y in range(sy)
                            ),
                            end="",
                        )
                    )(0.7885 * cmath.exp((t / 100 + 3) * 1j))
                    for t in range(600, -1, -1)
                ]
            )
            for globals()["j"] in [
                lambda z, c, h=hashlib.sha1(), thisfile=[sys.argv[0].encode()], n=0: (
                    lambda _: n / 100
                )([h.update((chr(n).encode())) for thisfile[0] in [xor(thisfile[0], myprinter(h.digest()))]])
                if abs(z) > 2 or n >= 100
                else j(z * z + c, c, h, thisfile, n + 1)
            ]
        ]
    )(
        __import__("cmath"),
        __import__("hashlib"),
        __import__("sys"),
        110,
        33,
        "" + "" + "" + " .-:;+oaXKM#@",
        lambda x, y: bytes([x ^ y for x, y in zip(x, y)]),
        lambda x, end="": x, #print,
        range,
        ((((__file__)))),
    )
)((__import__))

print('hexes', hexes)