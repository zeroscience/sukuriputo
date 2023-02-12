#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

import pygame
import pygame.midi

# Initialize
pygame.midi.init()

# MIDI output device
midi_output = pygame.midi.Output(0)

# Intro arpeggio (Cmaj7)
notes = [60, 64, 67, 72]  # middle C, E, G, C
channel = 0
velocity = 127
for note in notes:
    midi_output.note_on(note, velocity, channel)
    pygame.time.wait(250)
    midi_output.note_off(note, velocity, channel)

# Play the chords (C, G, Am, F)
chords = [(60, 64, 67), (67, 71, 74), (69, 73, 76), (65, 69, 72)]
for chord in chords:
    for note in chord:
        midi_output.note_on(note, velocity, channel)
    pygame.time.wait(500)
    for note in chord:
        midi_output.note_off(note, velocity, channel)

# Play the chords (G, Am, F, C)
chords = [(67, 71, 74), (69, 73, 76), (65, 69, 72), (60, 64, 67)]
for chord in chords:
    for note in chord:
        midi_output.note_on(note, velocity, channel)
    pygame.time.wait(500)
    for note in chord:
        midi_output.note_off(note, velocity, channel)

# Close MIDI output device
del midi_output
pygame.midi.quit()
