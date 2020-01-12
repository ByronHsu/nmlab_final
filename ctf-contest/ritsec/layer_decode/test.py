import re
import base64

with open('./onionlayerencoding.txt', 'r') as file:
    a = file.read()
    i = 0
    ll = [a]
    while(i < 100):
        lll = []
        print(i)
        for k in ll:
            try:
                a = base64.b64decode(k)
                if(len(a) > 0):
                    lll.append(a)
                    if(i>30):
                        print(a)
            except:
                pass
            try:
                a = base64.b32decode(k)
                if(len(a) > 0):
                    lll.append(a)
                    if(i>30):
                        print(a)
            except:
                pass
            try:
                a = base64.b16decode(k)
                if(len(a) > 0):
                    lll.append(a)
                    if(i>30):
                        print(a)
            except:
                pass
        ll = lll
        i = i + 1
        

# a = b"flag"
# print(a[0:3] == b'fla')
# b = b64encode(a)
# print(b)
# c = b64encode(b)
# i = 0
# print(c)
# while i < 10:
#     c = b64encode(c)
#     print(c)
#     i = i+1
