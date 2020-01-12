flag = '[.NBPx67m47\\26\\a7g\\74\\o2`0m60\\`k0`h2m5~'
zz = ''
for i in flag:
    zz = zz + chr(ord(i) ^ 3)

print(zz)