# 2022 交大程式安全 HW2 writeup

執行環境：2020 M1 macbook pro (arm晶片，非x86架構)\
code 在一般環境應該也可以跑

## [HW] AES

我是照著講師投影片 80～84 頁上面的方法做，就解出來了\
也就是說解題手法是用 CPA (Correlation Power Analysis)\
而 CPA 要用以前高中數學有教過的相關係數 (correlation coefficient) 公式去算相關性\
這個部分也不用自己慢慢代公式去算\
python 的 numpy 套件已經有算相關係數的 function 可以直接用\
參考資料：https://zhuanlan.zhihu.com/p/339384769?utm_id=0

說明一下如何用 numpy 來計算相關係數\
將兩筆資料放入 list 裡，轉為 numpy array 後\
傳入 corrcoef 這個 function 中

```python
import numpy as np

x = np.array([1, 3, 7, 9, 13])
y = np.array([-5, 2, -9, 11, 24])
print(np.corrcoef(x, y))
print(np.corrcoef(x, y)[1][0])
```
輸出結果：相關係數 $= 0.7798095288543354$

![image](https://github.com/YungPingXu/NYCU-Software-Security-2022/assets/52243909/9ef18e4c-49d5-4cdb-8e20-de9bf21e9618)

印出來會是一個 2 x 2 的矩陣\
而這兩筆資料的相關係數會放在左下和右上的對角線部分\
取左下 [1][0] 或取右上 [0][1] 都可以

考慮當兩筆資料為線性關係時，例如 $y=2x+3$
根據以前高中數學教的內容，此情況相關係數會等於 1
```python
x = np.array([1, 3, 7, 9, 13])
y = np.array([5, 9, 17, 21, 29]) # y = 2 * x + 3
print(np.corrcoef(x, y))
print(np.corrcoef(x, y)[0][1])
```
輸出結果：相關係數 $= 1$

![image](https://github.com/YungPingXu/NYCU-Software-Security-2022/assets/52243909/722ea65c-c087-4fa3-92d9-029ab2a6cbd0)

接下來開始寫程式來解題，首先看投影片這頁

![image](https://github.com/YungPingXu/NYCU-Software-Security-2022/assets/52243909/ab35ec8a-8e84-4e81-aa4e-d44880f68c49)

將題目給的 json 檔讀進來

```python
import json

with open('aes/stm32f0_aes.json') as json_file:
    data = json.load(json_file)

pt = []
pm = []
for i in data:
    pt.append(i['pt'])
    pm.append(i['pm'])

D = len(pt)
T = len(pm[0])
```
接下來要把明文分成一個一個 byte 去處理

![image](https://github.com/YungPingXu/NYCU-Software-Security-2022/assets/52243909/626ebc0a-b416-4b2c-9fea-432da6295362)

這邊解說先只考慮明文的第一個 byte\
key 總共會有 256 種可能 (0x00 ～ 0xFF，即 0 ～ 255)\
將每種可能分別乘上每一個明文的第一個 byte，然後到 Sbox 裡查表找對應的值\
在題目提供的 aes.c 原始碼裡可以找到 Sbox

![image](https://github.com/YungPingXu/NYCU-Software-Security-2022/assets/52243909/740e020c-ada4-48e6-b0d5-30b43347e9f3)

而 AES 加密過程中，到 Sbox 裡查表的方式這邊說明一下\
例如 0x57 的話，會到 Sbox 的第 5 個 row、第 7 個 column，也就是 Sbox[5][7]\
所以必須要實作把一個整數拆成分別求前面 8 個 bit 和後面 8 個 bit 的十進位值\
例如十進位的 67，二進位表示法是 01000011 (注意，要補滿到 8 個 bits)\
$0100=4$，$0011=3$，因此 16 進位表示法為 0x43\
查表的時候會去查 Sbox[4][3]\
(而 a、b、c、d、e、f 分別代表 10、11、12、13、14、15)

由於使用的 power model 是 Hamming Weight\
所以查表找出對應的值後，要算出二進位表示法總共有幾個 bits 是 1

![image](https://github.com/YungPingXu/NYCU-Software-Security-2022/assets/52243909/71c7290f-f72d-46f3-8462-a47cf54dd2b5)

程式碼如下

```python
def get_first_byte(n):
    binary_str = '{0:b}'.format(n).zfill(8)
    return int(binary_str[:4], 2)

def get_second_byte(n):
    binary_str = '{0:b}'.format(n).zfill(8)
    return int(binary_str[-4:], 2)

Sbox = [
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
]

K = 256
key_hypothesis = [k for k in range(K)]

M = []
    for d in range(D):
        row = []
        for k in range(K):
            n = pt[d][0] ^ key_hypothesis[k] # xor
            map_value = Sbox[get_first_byte(n)][get_second_byte(n)]
            row.append(bin(map_value).count('1'))
        M.append(row)
    assert len(M) == D and len(M[0]) == K
```
看剛才 step 4 那頁投影片，接下來要把算出來的矩陣 M 的每一個 column\
從 column 0 開始，一直到 column K-1\
分別去跟 pm 矩陣的每一個 column 計算相關係數\
M 的每一個 column 與 pm 矩陣的計算結果會存成一個 row\
然後重複 K 次 (矩陣 M 的 column 0 ～ K-1)\
所以最後會是 K x T 的矩陣

![](https://i.imgur.com/HXywDs7.png)

程式碼如下，這邊會先將原本的 pm 矩陣先做 transpose\
也就是把 row 變為 column，column 變為 row，然後存成矩陣 Y\
比較方便接下來算相關係數\
計算完畢後，將結果存在 M_corrcoef 矩陣

```python
import numpy as np

def corr_coef(list_x, list_y):
    x = np.array(list_x)
    y = np.array(list_y)
    return np.corrcoef(x, y)[1][0]

Y = []
for t in range(T):
    y = []
    for d in range(D):
        y.append(pm[d][t])
    Y.append(y)

M_corrcoef = []
for k in range(K):
    x = []
    for d in range(D):
        x.append(M[d][k])
    row = []
    for y in Y:
        corrcoef = corr_coef(x, y)
        row.append(corrcoef)
    M_corrcoef.append(row)
assert len(M_corrcoef) == K and len(M_corrcoef[0]) == T
```
接著去看算出來的相關係數中最大的那個，對應的 k 是多少，即為答案\
也就是說去看整個 M_corrcoef 矩陣中，最大的值是哪個\
其對應的 k 值就會是 key (flag 字串) 的第一個 byte\
得出 k 後，轉成在 ascii code 裡對應的字元\
就會是 key (flag 字串) 的第一個字
```python
flag = 0
max_corrcoef = 0
for k in range(K):
    for t in range(T):
        corrcoef = M_corrcoef[k][t]
        if corrcoef >= max_corrcoef:
            max_corrcoef = corrcoef
            flag = k
print(flag, chr(flag))
```
輸出結果：flag 的第一個字元是 1

![image](https://github.com/YungPingXu/NYCU-Software-Security-2022/assets/52243909/5c9d078a-829b-4886-a102-7656acbf7a3c)

由於這邊解說是只考慮明文的第一個 byte\
因此如果要把所有的 byte 都求出來的話\
在外層多加一層迴圈去跑每個 byte 就行 (flag 共有 16 個 bytes)\
於是，最後的解題程式碼就會是


```python
import json
import numpy as np

def get_first_byte(n):
    binary_str = '{0:b}'.format(n).zfill(8)
    return int(binary_str[:4], 2)

def get_second_byte(n):
    binary_str = '{0:b}'.format(n).zfill(8)
    return int(binary_str[-4:], 2)

def corr_coef(list_x, list_y):
    x = np.array(list_x)
    y = np.array(list_y)
    return np.corrcoef(x, y)[1][0]

Sbox = [
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
]

with open('aes/stm32f0_aes.json') as json_file:
    data = json.load(json_file)

pt = []
pm = []
for i in data:
    pt.append(i['pt'])
    pm.append(i['pm'])

D = len(pt)
T = len(pm[0])

K = 256
key_hypothesis = [k for k in range(K)]
answer = 'FLAG{'

for b in range(16):
    print(b)
    M = []
    for d in range(D):
        row = []
        for k in range(K):
            n = pt[d][b] ^ key_hypothesis[k] # xor
            map_value = Sbox[get_first_byte(n)][get_second_byte(n)]
            row.append(bin(map_value).count('1'))
        M.append(row)
    assert len(M) == D and len(M[0]) == K

    Y = []
    for t in range(T):
        y = []
        for d in range(D):
            y.append(pm[d][t])
        Y.append(y)

    M_corrcoef = []
    for k in range(K):
        x = []
        for d in range(D):
            x.append(M[d][k])
        row = []
        for y in Y:
            corrcoef = corr_coef(x, y)
            row.append(corrcoef)
        M_corrcoef.append(row)
    assert len(M_corrcoef) == K and len(M_corrcoef[0]) == T

    flag = 0
    max_corrcoef = 0
    for k in range(K):
        for t in range(T):
            corrcoef = M_corrcoef[k][t]
            if corrcoef >= max_corrcoef:
                max_corrcoef = corrcoef
                flag = k
    print(flag, chr(flag))
    answer += chr(flag)
answer += '}'
print(answer)
```
輸出結果

![image](https://github.com/YungPingXu/NYCU-Software-Security-2022/assets/52243909/65899030-9e59-40e9-8230-7fe4eb3d6134)


找出 flag
```sh
FLAG{18MbH9oEnbXHyHTR}
```

不過這個跑了蠻久的，跑了好幾分鐘才跑完\
演算法方面好像不太能優化時間複雜度了
