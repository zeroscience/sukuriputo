#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

import pygame
import pygame.midi

# Initialize MIDI module from pygame
pygame.midi.init()

# Set MIDI output device
midi_output = pygame.midi.Output(0)

# Play a middle C note on channel 0 with a velocity of 127
note = 60  # middle C
channel = 0
velocity = 127
midi_output.note_on(note, velocity, channel)

pygame.time.wait(1000)

# Turn off the note
midi_output.note_off(note, velocity, channel)

# Close MIDI output device
del midi_output
pygame.midi.quit()
