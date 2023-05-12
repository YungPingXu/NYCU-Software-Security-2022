# 2022 交大程式安全 HW1 writeup

執行環境：2020 M1 macbook pro (arm晶片，非x86架構)
不過這些 code 在一般環境也可以跑就是了

## [LAB] COR
聽同學說如果用 python 跑這題爆破的話，連 CPU 超強的 M1 mac 也要跑一整晚，而且我也不太想用自己的電腦跑爆破，再加上不太想用 C++ 來實現，兩種方式都很麻煩，而且分數太少，只有 20 分，所以先放棄了

## [LAB] POA

## [HW] LSB
這題基本上就是個 RSA 的解密器，不過它不會直接印出解密後的明文，而是印出 (明文 mod 3)，但是講師上課時教的是 mod 2 的解法，無法直接用在這題身上，那該怎麼辦？

```python
#! /usr/bin/python3
from Crypto.Util.number import bytes_to_long, getPrime
import os

from secret import FLAG

p = getPrime(1024)
q = getPrime(1024)
n = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = pow(e, -1, phi)

m = bytes_to_long(FLAG + os.urandom(256 - len(FLAG)))
assert m < n
enc = pow(m, e, n)
print(n)
print(e)
print(enc)
while True:
    inp = int(input().strip())
    pt = pow(inp, d, n)
    print(pt % 3)
```
我是參考了這篇 github repo 底下所寫的數學公式
不過完全不需看 source code
它的 code 我覺得對解題沒什麼幫助，我寫的 code 也和它不同
https://github.com/kuruwa2/ctf-writeups/tree/master/BambooFox%20CTF/oracle

首先要先看懂數學公式
$3^{-1}$ 是指 3 在 mod n 之下的模反元素 (modular inverse)
自己乘上自己的模反元素會等於 1 (在 mod n 之下)，因此可以直接消去 1 次方
然後 mod 3 可以直接消去前面那些有乘上 3 的項，是因為 3 可以提出來
而剩下的部分有可能大於 3，所以要 mod

(1) 密文 $=$ enc，明文 $=$ pt，回傳 pt mod 3
而我們可以把 pt 分解成 3 的多項式
$pt=a_n\cdot{3^n}+a_{n-1}\cdot{3^{n-1}}+a_{n-2}\cdot{3^{n-2}}+\cdot\cdot\cdot+a_{2}\cdot{3^{2}}+a_{1}\cdot{3}+a_0$
回傳 $r =pt$ mod $3=a_0$

$\Rightarrow a_0=pt$ mod 3

而講師投影片裡有提到這個性質
送的密文乘上多少的 e 次方，對應的明文就是乘上多少
![](https://i.imgur.com/MbVKXp6.png) ![](https://i.imgur.com/YVLxp18.png)
以這題來說，密文 $=(3^{-n})^e \cdot enc$，明文 $=3^{-n} \cdot pt$

(2) 密文 $=(3^{-1})^e\cdot enc$，明文$=3^{-1}\cdot pt$
$3^{-1}\cdot pt=a_n\cdot{3^{n-1}}+a_{n-1}\cdot{3^{n-2}}+a_{n-2}\cdot{3^{n-3}}+\cdot\cdot\cdot+a_{2}\cdot{3^{1}}+a_{1}+a_0\cdot3^{-1}$
回傳 $r=(3^{-1}\cdot pt)$ mod $3=a_1+((a_0\cdot3^{-1})$ mod n$)$ mod 3

$\Rightarrow a_1=r-((a_0\cdot3^{-1})$ mod n$)$ mod 3

(3) 密文 $=(3^{-2})^e\cdot enc$，明文 $=3^{-2}\cdot pt$
$3^{-2}\cdot pt=a_n\cdot{3^{n-2}}+a_{n-1}\cdot{3^{n-3}}+a_{n-2}\cdot{3^{n-4}}+\cdot\cdot\cdot+a_{3}\cdot{3^{1}}+a_{2}+a_1\cdot3^{-1}+a_0\cdot3^{-2}$
回傳 $r=(3^{-2}\cdot pt)$ mod $3=a_2+((a_1\cdot3^{-1}+a_0\cdot3^{-2})$ mod n) mod 3

$\Rightarrow  a_2=r-((a_1\cdot3^{-1}+a_0\cdot3^{-2})$ mod n) mod 3

(4) 密文 $=(3^{-3})^e\cdot enc$，明文 $=3^{-3}\cdot pt$
$3^{-3}\cdot pt=a_n\cdot{3^{n-3}}+a_{n-1}\cdot{3^{n-4}}+a_{n-2}\cdot{3^{n-5}}+\cdot\cdot\cdot+a_{4}\cdot{3^{1}}+a_{3}+a_2\cdot3^{-1}+a_1\cdot3^{-2}+a_0\cdot3^{-3}$
回傳 $r=(3^{-2}\cdot pt)$ mod $3=a_2+((a_2\cdot3^{-1}+a_1\cdot3^{-2}+a_0\cdot3^{-3})$ mod n) mod 3

$\Rightarrow  a_3=r-((a_2\cdot3^{-1}+a_1\cdot3^{-2}+a_0\cdot3^{-3})$ mod n) mod 3

$a_1$ 到 $a_n$ 都算出來後，就破解出明文 (flag)
而這個演算法一看就知道佔據最多時間複雜度的在 r 減去的那一大串東西
如果實現上完全沒有優化的話
可能會因為時間複雜度太高而要跑很久，或是跑不出來
$(1+2+3+\cdot\cdot\cdot+n=O(n^2))$
因此要想辦法降低時間複雜度，那要如何降低？

仔細觀察 r 減去的那一大串東西，可以發現
下一個的值可以用上一個的值來計算，而不需要整個重新算

$t_1=(a_0\cdot3^{-1})$ mod n
$t_2=(a_1\cdot3^{-1}+a_0\cdot3^{-2})$ mod n
$t_3=(a_2\cdot3^{-1}+a_1\cdot3^{-2}+a_0\cdot3^{-3})$ mod n

觀察後可以發現

$t_n=(a_{n-1}\cdot3^{-1}+t_{n-1}\cdot\ 3^{-1})$ mod n 

如此一來，用這個計算的話，算一次的時間複雜度變為常數時間
總共的時間複雜度降為 $O(n)$

接下來是實現的部分
$a_0$ 到 $a_n$ 存到 a 這個 list 裡
m 最後會是解出來的明文 (flag)

```python
from pwn import *
from Crypto.Util.number import long_to_bytes, inverse

r = remote('edu-ctf.zoolab.org', 10102)
n = int(r.recvline().strip().decode())
e = int(r.recvline().strip().decode())
enc = int(r.recvline().strip().decode())

r.sendline(str(enc).encode())
a = [] # [a_0, a_1, a_2, ...]
a_0 = int(r.recvline().strip().decode())
a.append(a_0) # a_0
m = a[0] * (3 ** 0) # a_0 * 3^0

inv_3 = inverse(3, n) # modular inverse of 3 to n
i = 1
t = 0

while True:
    send_msg = (pow(inv_3, e*i, n) * enc) % n
    r.sendline(str(send_msg).encode())
    recv_msg = int(r.recvline().strip().decode())
    t = (a[i-1] * inv_3 + inv_3 * t) % n
    a.append((recv_msg - t) % 3) # a_i
    m += a[i] * (3 ** i) # a_i * 3^i
    flag = long_to_bytes(m)
    if b'flag' in flag or b'FLAG' in flag:
        print(flag)
        break
    i += 1
```
![](https://i.imgur.com/zoMVYSN.png)

找出 flag
```
FLAG{lE4ST_519Nific4N7_Bu7_m0S7_1MporT4Nt}
```
不過，即使是我的 M1 mac
也要跑 50 幾秒，一般 windows 電腦可能要跑數分鐘

![](https://i.imgur.com/lwcGaBv.png)

## [HW] XOR-revenge

題目有 getbit，也就是在考 LFSR
而第 15 行則是把 FLAG 字串裡的每個字元轉換成 ascii code 後併在一起
並以整數 0 和 1 的形式放在 flag 這個 list 裡
接著跑雙迴圈，外迴圈跑 flag list 的長度 + 70
內迴圈跑 36 次 getbit，跑完後再 getbit 一次
並將輸出結果放進 output list 裡，總共 getbit 37次
然後把 output 和 flag 裡的元素進行 xor 運算
並印出結果 (我們拿到的文字檔 output.txt)
其中，原本的 output 最後面的 70 bits 是沒有被 xor 過的
而這就是這題的重點了，或許可以拿來回推原本的 state

```python
import random

from secret import FLAG

state = random.randint(0, 1 << 64)

def getbit():
    global state
    state <<= 1
    if state & (1 << 64):
        state ^= 0x1da785fc480000001
        return 1
    return 0

flag = list(map(int, ''.join(["{:08b}".format(c) for c in FLAG])))
output = []
for _ in range(len(flag) + 70):
    for __ in range(36):
        getbit()
    output.append(getbit())

for i in range(len(flag)):
    output[i] ^= flag[i]

print(output)
```
那我們要如何透過沒有被 xor 過的那 70 bits 來回推出原本的 state？
這個部分我卡了很久
直到看到講師投影片中有出現 companion matrix 的內容

![](https://i.imgur.com/UF6kx0B.png)

![](https://i.imgur.com/JwNcuDi.png)

但是看完後似乎還是覺得對解題沒有幫助
繼續查了許多資料後，看到了這篇文章
https://en.m.wikipedia.org/wiki/Linear-feedback_shift_register
看完後才發現講師的投影片裡的是 Fibonacci LFSR
而題目裡的 getbit 有 if 的條件判斷式以及會去 xor 一個常數
因此得出題目應該是 Galois LFSR 的形式
往下看到 Matrix forms 的部分，裡面有說到
用 LFSR 的特徵多項式求出相伴矩陣後
如果已知目前的 state，那麼我們就可以利用此相伴矩陣
直接求出任意 k 個 step 後的 state
也就是說，相伴矩陣其實是 LFSR 的狀態轉移矩陣
於是想先求得 state 的相伴矩陣，求相伴矩陣前必須先求出特徵多項式

```python
# sage code

state = 0x1da785fc480000001
lst = []
for _ in range(65):
    lsb = state & 1 # least significant bit
    state >>= 1
    if lsb:
        lst.append(1)
    else:
        lst.append(0)
print(lst)
Z2 = Zmod(2) # field for mod 2
f = PolynomialRing(Z2, 'x')
char_poly = f(lst) # characteristic polynomial
print(char_poly)
Cm = companion_matrix(char_poly, 'left')
```
第 1 行的 state 就是題目的 getbit 裡面的 state 去 xor 的常數
而 state & 1 則是求 state 的最低位元
Zmod(2) 是指將多項式或矩陣的場域指定為在 mod 2 之下
求出特徵多項式後，接著參考此文件
https://doc.sagemath.org/html/en/reference/matrices/sage/matrix/special.html#sage.matrix.special.companion_matrix
得知 sagemath 裡可以直接用這個求出相伴矩陣
不過我當時在這邊有踩了一個坑
就是 companion_matrix 的第二個參數預設會是 right
難怪不管怎麼樣都求不出 Galois LFSR 的相伴矩陣的形式
因此這邊必須要指定成 left，求出的相伴矩陣才會是正確的
(讓相伴矩陣去乘一次 state vector，就相當於 getbit 一次)

![](https://i.imgur.com/XMIpmTP.png)

那既然我們有了可以任意求之後某個狀態的相伴矩陣後
再加上 output 後面 70 bits 都沒有跟 flag xor 過
因此我們想要求出 output 後面 64 bits 的 initial state
另外，題目裡的外迴圈跑一次是會進行 37 次的 getbit
因此相伴矩陣也要乘 37 次，所以把它 37 次方
接著透過 M 與其反矩陣回推出 initial state
$(M \cdot s0=s$，則 $s0 =M^{-1} \cdot s)$
```python=
Cm ^= 37
M = matrix(Z2, 64)
for i in range(64):
    M[i] = (Cm^(i+343))[-1]

output = [1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0]

last64 = output[-64:] # last 64 bits
last64_v = vector(Z2, output[-64:])
M_inv = M^(-1) # inverse of matrix M
initial_state = M_inv * last64_v
```
![](https://i.imgur.com/yifyrdg.png)

![](https://i.imgur.com/E6sumDU.png)

有了 initial state 後，就可以用相伴矩陣直接算出之後的每個 state，並且得到原本還沒有被 xor 的 output

```python
origin_output = []
state = initial_state
while len(origin_output) != len(output):
    state = Cm * state
    origin_output.append(state[63])
print(origin_output)
```

![](https://i.imgur.com/HwxkBp5.png)

求出原本還沒被 xor 的 output 後
將它與最後的 output 進行 xor，即為 flag 了
不過這邊要注意的地方是，sagemath 裡的 ^ 運算子是代表次方
而不會是 xor，因此這邊要寫成相加後 mod 2
因為 xor 相當於 mod 2 之下的加法

```python
flag = []
for i in range(len(output)):
    flag.append((origin_output[i] + output[i]) % 2) # xor
print(flag)
```
![](https://i.imgur.com/yTSLcml.png)

接著就能還原出原始的 flag 字串了

```python
answer = ''
for i in range(len(flag)//8):
    s = ''
    for j in flag[i*8:(i+1)*8]:
        s += str(j)
    answer += chr(int(s, 2))
print(answer)
```
![](https://i.imgur.com/W88pGPR.png)

找出 flag
```
FLAG{Y0u_c4N_nO7_Bru73_f0RCe_tH15_TiM3!!!}
```


## [LAB] dlog

題目如下

```python
#! /usr/bin/python3
from Crypto.Util.number import isPrime, bytes_to_long
import os

from secret import FLAG

p = int(input("give me a prime").strip())
if not isPrime(p):
    print("Do you know what is primes?")
if p.bit_length() != 1024:
    print("Bit length need to be 1024")

b = int(input("give me a number").strip())
flag = bytes_to_long(FLAG + os.urandom(p.bit_length() // 8 - len(FLAG)))

print('The hint about my secret:', pow(b, flag, p))
```
首先，找一個 smooth 的質數 p
smooth 的質數指的是 p-1 會很好做質因數分解
所含的質因數不能太大，否則在做質因數分解時會耗時很久又或者分解不出來

因此，寫一個 script 來找一個這樣子的 p
不過這邊我原本是用 $2^a\cdot3^b\cdot5^c\cdot7^d\cdot11^e$
但後面發現會行不通，於是把 5 替換成 13
```python
from Crypto.Util.number import isPrime

def find_p():
    for a in range(70, 100):
        for b in range(70, 100):
            for c in range(70, 100):
                for d in range(70, 100):
                    for e in range(70, 100):
                        n = pow(2, a) * pow(3, b) * pow(7, c) * pow(11, d) * pow(13, e)
                        p = n + 1
                        bit_length = p.bit_length()
                        if bit_length == 1024:
                            if isPrime(p):
                                print(p)
                                return
if __name__ == '__main__':
    find_p()
# 152744294539980278765788801076585501079291523535506767726528521659770180869558164735520354233835785112664566361223221199010317411576452139281249651354892890084065538849953042358630895664091423884100199777813162378714287549397127837484641466570258023960655053217116819465388863584753232085018550501639251296257
```
將找出來的這個質數 p 丟給它，而第二個數字 b 則丟給他 2～15 之間的整數
接著它會回傳 secret，然後將此值給 ct 這個變數，而 b 送什麼值就給什麼值

![](https://i.imgur.com/IggVjMC.png)

```python
# sage code

p = 152744294539980278765788801076585501079291523535506767726528521659770180869558164735520354233835785112664566361223221199010317411576452139281249651354892890084065538849953042358630895664091423884100199777813162378714287549397127837484641466570258023960655053217116819465388863584753232085018550501639251296257
ct = 36558024411054279014957070006710086810402239423132964312469315433987765677899098999708350783587178828473540196446264128052897139023732485058990856783269441435936836982608570758467035231276788678418739772334961398986969064649302482302397407574729105872739598510773620365268040643155253370444449040625047258657
b = 2
b = Mod(b, p)
ct = Mod(ct, p)
discrete_log(ct, b)

from Crypto.Util.number import long_to_bytes
print(long_to_bytes())
```
![](https://i.imgur.com/hkJAsZe.jpg)

重複同樣的流程幾遍後，發現當 b = 5 時會印出 flag
但是上傳到課程網站上卻說是錯的，代表這個不是真的 flag

![](https://i.imgur.com/FdemIwO.png)

![](https://i.imgur.com/7zPhgy7.png)

於是繼續試下去，當 b = 10 時，出現了第 2 次 flag
而這次上傳到課程網站上，答案就正確了～

![](https://i.imgur.com/mIytNwO.png)

![](https://i.imgur.com/lBpzdTF.png)

找出 flag
```
FLAG{D0_No7_SLiP!!!1t'5_SM0o7h_OwO}
```

## [BONUS] Signature

## [HW] DH

首先觀察題目，題目會先給你一個質數 p
接著我們要給一個輸入 g，而 p、a、b 都是不可控的
輸出結果 c 基本上可以看成 $(g^a)^b \cdot$ flag (全部都是在 mod p 之下)
如果 $(g^a)^b = 1$，那麼印出來的 c 就是 flag 了
因此題目才會禁掉 $g=1$ 和 $(g^a)=1$ 的情況，以防 flag 被洩露出去

```python
#! /usr/bin/python3
from Crypto.Util.number import bytes_to_long, getPrime
import random
from secret import FLAG

p = getPrime(1024)
assert bytes_to_long(FLAG) < p
print(p)

g = int(input().strip())
g %= p
if g == 1 or g == p - 1:
    print("Bad :(")
    exit(0)

a = random.randint(2, p - 2)
A = pow(g, a, p)
if A == 1 or A == p - 1:
    print("Bad :(")
    exit(0)

b = random.randint(2, p - 2)
c = pow(A, b, p) * bytes_to_long(FLAG) % p
print(c)
```
而題目也禁掉了 $g=p-1$ 和 $(g^a)=p-1$ 的情況
由此猜測 $(p-1)$ 的任意次方(在 mod p 之下) 有可能會等於 1
實際寫一段 code 來測試看看
```python
p = 29 # prime
for i in range(10):
    print(pow(p-1, i, p))
```
輸出結果會是 1, 28, 1, 28, 1, 28 ... 一直循環
即使把 p 換成不同的質數，也會有一樣的現象 (1, p-1, 1, p-1, ...)
也就是說有高機率(二分之一機率)答案會是 1
因此也禁掉了此情況，以防 flag 被洩露出去

那我們要給定什麼樣的 g，才能讓 $(g^a)^b = 1$？
老實說這部分我卡關很久
之後是因為想到題目的 hint 有給 sage 裡的 sqrt function 用法
於是想說把上面那段 code 開根號看看

不過，在開根號前，先把那段 code 寫成 sage code 的形式
```python
p = 29 # prime
for i in range(10):
     t = Mod(p-1, p)
     print(t**i)
```
![](https://i.imgur.com/9lB3hgR.png)

確定 code 沒有寫錯，接著把他開根號

```python
p = 29 # prime
for i in range(10):
     t = sqrt(Mod(p-1, p))
     print(t**i)
```

![](https://i.imgur.com/RtGhd1a.png)

從輸出結果中也會發現，每 4 次會有一次答案是 1
也就是說，輸出結果有四分之一機率答案會是 1
即使把 p 換成不同的質數，也會有一樣的現象

那如果將 p 代換成題目一開始印出來的質數 p，會怎麼樣？
實際測試看看～

![](https://i.imgur.com/LCMZ6E4.png)

```python
for i in range(5):
    t = sqrt(Mod(p-1, p))
    print(t**i)
```
![](https://i.imgur.com/MNC1WuX.png)


果然，確實是 4 個一循環，答案有四分之一機率會是 1
這樣的話，我給它的輸入 g 代 t (即圖片中選取起來的部分)
然後手動爆破所有可能，不就好了？
因為 $(g^a)^b$ 基本上可以直接看成 $g^i$ (g 的任意次方)
只要 $g^i=1$ 的話，印出來的 c 就會是 flag 了

將輸入 g 代 t

![](https://i.imgur.com/oycCJpI.png)

接著把印出來的輸出結果 c 過 long_to_bytes
```python=
from Crypto.Util.number import long_to_bytes
long_to_bytes()
```

![](https://i.imgur.com/rxSIhLt.png)

結果沒有出現 flag，代表沒有命中四分之一機率
於是我再重複多試了幾次

![](https://i.imgur.com/juzFH77.png)

```python
sqrt(Mod(p-1, p)) # t
```
![](https://i.imgur.com/bJTECht.png)

最後終於命中四分之一機率了！找出 flag
```
FLAG{M4yBe_i_N33d_70_checK_7he_0rDEr_OF_G}
```
(當初試了 10 幾次才成功，我可能太非了XD)

不過在過程中有可能會出現另外兩種情況

第一種：在 mod p 下的根號 (p-1) 不存在
這種情況他會直接印 sqrt(p-1) 出來

![](https://i.imgur.com/Em4jbQm.png)

![](https://i.imgur.com/wlKKgf6.png)

第二種：被回 Bad，因為 $g^a$ 有可能會等於 1

![](https://i.imgur.com/DJJr0K9.png)

![](https://i.imgur.com/jmdKHza.png)

遇到這兩種情況時就直接重來就好

## [HW] node














