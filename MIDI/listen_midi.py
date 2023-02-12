#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# It will raise an exception if no MIDI attached
#
# Console output
# --------------
# (60, 40, 0)
# (60, 0, 0)
# (60, 47, 0)
# (60, 0, 0)
# (60, 34, 0)
# (60, 0, 0)
# (60, 1, 0)
# (60, 0, 0)
# (60, 48, 0)
# (60, 0, 0)
# (60, 93, 0)
# (60, 0, 0)
#
# notes.txt output
# ----------------
# [[144, 60, 73, 0], 2692]
# (60, 73, 0)
# [[128, 60, 0, 0], 7214]
# (60, 0, 0)
# [[144, 60, 28, 0], 10788]
# (60, 28, 0)
# [[128, 60, 0, 0], 19812]
# (60, 0, 0)
# [[144, 60, 66, 0], 21283]
# (60, 66, 0)
# [[128, 60, 0, 0], 25513]
# (60, 0, 0)
# [[144, 60, 93, 0], 26348]
# (60, 93, 0)
# [[128, 60, 0, 0], 29150]
# (60, 0, 0)
#
# Tested on Launchkey 49 MIDI keyboard by Novation
#

import pygame
import pygame.midi

# Initialize MIDI module
pygame.midi.init()

# Set MIDI input and output device
midi_input = pygame.midi.Input(1)
midi_output = pygame.midi.Output(0)

# Set the volume of the output device
volume = 127  # Range: 0-127
#midi_output.set_volume(volume)
#midi_output.control_change(7, volume, 0)

with open("notes.txt", "w") as f:
    # Listen for MIDI input and play it on the output device
    while True:
        # Check for new MIDI events
        if midi_input.poll():
            # Get the events
            events = midi_input.read(10)
            for event in events:
                f.write(str(event) + "\n")
                print(str(event))
            # Prepare the events for the pygame.midi.Output class
            notes = [(event[0][1], event[0][2], event[0][3]) for event in events]
            # Play the notes on the output device
            for note in notes:
                midi_output.note_on(note[0], note[1], note[2])
                print(note)

# Close MIDI input and output devices
del midi_input
del midi_output
pygame.midi.quit()
