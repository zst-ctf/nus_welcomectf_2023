
def xor(var, key):
    return bytes(a ^ b for a, b in zip(var, key))

lines='''
4c04a02f06b385b23d305cdd80c52884ed9161e6073dc39dc241db9719f17b64424a4a0e431ac5badb1bc9d9e4c121c87007589edcf0b33bd9837547958d6c
4d1da22e5ff293b6647a0ec08dce6c9be1df20fa0723c7829108c1df0ced3e28464e5d405e1b82ead614d4d5b7c53bdf701a5edbd1b8b97dc8907e099f8b6a4adb14803cbbf11ae64c75f7582745d0c9c05759d6e9bd
4802b5311ae0c1b236795cc8c8d47187fddf2ef24e28d49b8b5c95c305f86a644c4a55050a1dccbade1ccb9ff2d630d5244e55d1c4f7a4689c99794299c3795cda18c13dbdf10da80234fa5a3045c8c2c81b42ce
5e1aa0335fe789b6646f09c7c8c76792ebdf25fb19208ace9640d0971ef267644c4d590e4d11d1bad91ac196e58434d5344e54dbcbf7bb7ecfd5604092882719d1468034a8f144e64f7aff142410c3d7c812
4014e52410e6c1bb217d08899fc17c92eadf2efa4e3ace8bc25bc1d81bfc3264465118135e15d0eec955d996b7c620d93202539ec9f6b23bdb90645adc916e58d258987aa7fb1c
4b1bb7390cb392ba2a7b5cda87ce6f84b8962fb41a26c3ce965ad0d21eb53e25414118144211cbe89a18c895f8c03cde234e55dfc6b8b47e9c9d75488e872b50d0149532aab405a95c7af25a33
5d1aa07d12fc8ebd647f1dc7c8c26dd7eb9a24fa4e2fd2ce8c41d2df19b53e25414118134519c7eed318c88ab7cd219b3c0159d5dbb8ba72d7903048dc81625e9e578828acf80de6477abb403c0091d4cf0e
5a1da63e1ae1c1ba373c1d898fc16592b88829f11c2b869e8747c5db08b9752d4c4e18010a16c3f6d655cc97f38421c9294e42d188ebb574ce90304e9382674a9e55863ba6fa1bb20e60f351740ac5cfc1050dcdf5afac
5b17a43916fd86f3267313c29b806184b89e61f21b208699835195c302b972214e5756404411d5bace1dc497f0d775da3e0a16d7c5f9b172d290304c8480624dd75a867abce007b44771e8
5d00a0380cb391a12b6a15cd8d807b9ff99b24b4012086868d5c95d30ce06d680f4456040a0dcdef9a16cc97b7d73ccf701b58dacdeaf66fd4907d09888c2b4aca55987aacfb07aa
4a13b12e5fff88b8213c08c6c8c36096eb9a61f5083ac39cc25bc1c504f779370f4456040a04cefbc355da90e3cc75c83d0f5ad288ecb962cf
5b13ac331dfc96a0647d0cd98dc17ad7f19161e0062b869d895195d60bed7b360f4c4c405815cbf4c9598d98f9c075cf380b4f9ec0f9a07e9c98714785c36856d25b9329
4a13b72e5ffb80a5213c0bc18dc56484b89e2ff04e2bc8898b46d0c441b97f2a4b0548054504ceff9a00de9cb7d03dde3d4e42d188ffb93bc89a304d95856d5ccc518f2eefe404a74d71e8
5a05ac3012fa8fb464750f8989807f96ec9a33b40f2dd2879441c1ce4dee76215d4018104f1bd2f6df55c096e1c175cf380b5fcc88f9a476cfd5714798c3675cd947c12ea0b41bb24f6dbb553209dec6d0
401ce52a16fd95b636305cda86cf7fd7fe9e2df81d6ec09c8d4595c305fc3e37445c1801441082f9d503c88be48421d3354e51ccc7edb87f9c9c7e098b8b624ddb
411db02e1ae0c1b236795cde80c57a92b88f24fb1e22c3ce8e41c3d241b97f2a4b054c084f0d82f2db03c8d9e5cb3ad6234e50d1dab8a577d990604092842719db559533a1f344e64f7aff142600ddc6dc1e43de
5d1aa07d10f084b22a3c15dac8c12895f19861f6012adfce8d4e95c00ced7b360f5251144254d5fbcc10ded9f6ca319b340750d8cdeab375c8d57b4092877819d152c129aaf548a55c71fa402117d4d4
4b1ba6241cff84a064741ddf8d807c80f7df36fc0b2bca9dc249dbd34de97b204e494b4c0a15ccfe9a0cc28cb7c734d5701c5fdacdb8a273d998304f93912b5fcb5ac135bdb41ca90e73fe407404c3c8d11949
4f1eaa2a1ae192f3277311ccc8c966d7f59e2fed4e3dce8f924dc6970cf77a644c4a540f58078ebadb1bc9d9e3cc30c2701d5bdbc4f4f669d9947c4585c36550dd51
5e1aa0335fea8ea6647013c683807d87b89e35b40027c186960495ce02ec3e274e4b18134f1182e9ce14df8ab7d022d23e055ad7c6fff672d2d5644199c36f58cc5fc129a4ed
5d1aa07d19ff80b47e3c1bdb8dd96096ec8c3afa5d1895bcbd7dc68432a970777051090d192bf2aefe2ac0c9e5970a8c385a58e198f6b528c1
'''.strip().splitlines()

lines = list(map(bytes.fromhex, lines))

known_pt = b"greyhats{".ljust(87, b'_')

def search_known_pt(known_pt, line_index):
    key = xor(lines[line_index], known_pt)
    print('known_pt', known_pt)
    print('key', key)

    for i, l in enumerate(lines):
        pt = xor(l, key)
        print(f'pt{i}:', pt)


# The original plaintext.txt file contains 21 lines. 
# Each of the first 20 lines contain an English sentence (total of 20 English sentences). 
# The last line contains the content of the flag.

### Find which one is for greyhats{ flag format.
if False:
    for offset in range(80):
        known_pt = (b"_" * offset) + b"greyhats{".ljust(87, b'_')
        search_known_pt(known_pt, -1)
        input(f"Index {x} - Next?")
    quit()


### We get the following result at offset 10.
known_pt = b'__________greyhats{______________________________________'
line_index = 20

### The following was filled in manually by comparing the text knowing that they are english sentences.

known_pt = b'OX]\x0c\x19RL]Efriendly a_\x05d\ras*X\x04a\x1b\x11\x00i@\x0b\x12\x18o/\x1bwaKC\r\rn\x0c\x17\x1fYe\x16\x11S\nV'
line_index = 1

known_pt = b'\\__\x11\x19JQMElook up at \x02`\x0bet&\x0c\x15o\x1a\x11\x0faENA\te/\x18oa@\x1c\r\x18w\x01Y\x00]i\x01V\x1c\x05L'
line_index = 19

known_pt = b'M[U\x08\\AM\x18\x06ome in many z\x04lpo_La\x01ULcD\x02]\x1es#KznVOY\x04e\x11\x17\x18\\e\x03]\x1c\x1eG'
line_index = 18

known_pt =  b'BY\x1a\x08P]J]\x17, snow falls \n\x7fog\x0c\x18h\n\x11\x1fkRNS\x02d/\x08tvW\x1d^Lt\x00RKVr\x00DR\x08\x02'
line_index = 14

known_pt = b'CXO\x0c\\@\x1eY\x17e where people lcZ\t,OP\x02d\x0b\x1aZ\ty/\x03zvWO_\x03o\x05DKWo\x1d\x11O\x00G'
line_index = 15

known_pt = b'X@S\x12TZP_Eis a water activity \x18Y\trNNB\to\x7f\x07~ _\x00[\t \x1c_\x0eXrOPN\x01Q'
line_index = 13

known_pt = b'____VP[Y\x0b is a big body of water \\\x07F\x04 x\nmeAOL\x02dHS\x02Wf\nCY\x02V'
line_index = 16

known_pt = b'I^Y\x06Z_[KEhave two wheels and pedals\x1eLaa\x0f;y]\x1a\r\x0fa\x06\x17\x19Xd\n\x11H\x04G'
line_index = 17

known_pt = b'_________ greyhats{n3V3R_Us3_0n3_t1m3____________________'
line_index = 20

known_pt = b'NA_\r@\x13ZY\x1c, the sun rises in the morning znVO^\tt\x1b\x17\x02_ \x1bYYLG'
line_index = 0

known_pt = b'_________ greyhats{n3V3R_Us3_0n3_t1m3_P4D________________'
line_index = 20

known_pt = b'\\__\x11\x19JQMElook up at night, you can see stars \x18w\x01Y\x00]i\x01V\x1c\x05L'
line_index = 19

known_pt = b'HVN\x0c\x19_WS\x00 to chase after strings and play with \x1bZ\n]lOES\x15Q'
line_index = 10

known_pt = b'JGJ\x13\\@\x1eY\x17e a type of fruit that come in different KRo\x03^N\x1f\x02'
line_index = 2

known_pt =  b'BQ\x1a\x06VF\x1eP\x00at water on the stove, it starts to bubbleb\x02H\x1dX\x0b'
line_index = 4

known_pt = b'NA_\r@\x13ZY\x1c, the sun rises in the morning and sets in theX\t'
line_index = 0

known_pt = b'\\__\x11\x19GV]Esun goes down, the sky changes color and becomes\x1f'
line_index = 3

search_known_pt(known_pt, line_index)

# pt20: b'_________ greyhats{n3V3R_Us3_0n3_t1m3_P4D_m0r3_7h4n_0nc3}'
