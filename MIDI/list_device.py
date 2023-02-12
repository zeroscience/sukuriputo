#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

import pygame.midi

def print_devices():
    for n in range(pygame.midi.get_count()):
        print (n,pygame.midi.get_device_info(n))

if __name__ == '__main__':
    pygame.midi.init()
    print_devices()
