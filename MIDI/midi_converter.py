#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

import mido

# Load MIDI file
midi_file = 'input.mid'
midi = mido.MidiFile(midi_file)

# Extract main single notes from the MIDI file
notes = []
for track in midi.tracks:
    for event in track:
        # Check if event is a note on event
        if event.type == 'note_on':
            # Check if velocity is non-zero (note is not a release event)
            if event.velocity > 0:
                # Check if note is not already in the list
                if (event.note, event.velocity) not in notes:
                    # Add note to the list
                    notes.append((event.note, event.velocity))

# Write notes to a file
with open('notes.txt', 'w') as f:
    f.write('notes=')
    f.write(str(notes))
    
