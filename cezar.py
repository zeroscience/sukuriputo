#!/usr/bin/env python3
#
# Shifra Cezar
# Version: Kumanovo/SE
# Env: EDU
# Debug: ON
#
# lqwrm, 2021
#

import string

print()
tajna = ''
kljuch = 17
tabche = '\t\t'
azbuka = string.ascii_uppercase
poruka = input('Poruka: ').upper()
#azbuka = 'abcdefghijklmnopqrstuvwxyz'.upper()

print('Menjam:', poruka, '\nKljuch:', kljuch, '\n')

for bukva in poruka:
  if bukva in azbuka:
    print('Karakter:\t', bukva)
    pozicija = azbuka.find(bukva)
    print('Pozicija:\t', pozicija)
    shifra = pozicija + kljuch
    print('Shifra:{} {}'.format(tabche, shifra))
    if shifra < len(azbuka) - 1:
      tajna += azbuka[shifra]
      print('Tajna:{} {}'.format(tabche, tajna))
      print('-' * int(len(tajna) + int(len(tabche)) + 15))
    else:
      tajna += azbuka[shifra - len(azbuka)]
      print('Tajna:{} {}'.format(tabche, tajna))
      print('-' * int(len(tajna) + int(len(tabche)) + 15))
  else:
    tajna = tajna + bukva
    #print(''Tajna:', tajna') # znaci

print('\nPoruka:', poruka)
print('Enkriptirana poruka:', tajna, '\n')
