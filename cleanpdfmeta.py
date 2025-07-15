#!/usr/bin/env python
#
# Script that strips metadata from Word-generated PDF file.
# lqwrm, 2025
#

import pikepdf
import sys
import time
import itertools

def anime(text, duration=2):
    spinner = itertools.cycle(['|', '/', '-', '\\'])
    end_time = time.time() + duration
    while time.time() < end_time:
        sys.stdout.write(f'\r{text} {next(spinner)}')
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\r' + ' ' * (len(text) + 2) + '\r')

def metaclean(input_pdf, output_pdf):
    print(f"[+] Opening PDF: {input_pdf}")
    anime("Analyzing PDF structure")

    with pikepdf.open(input_pdf) as pdf:
        print("[*] Removing document metadata...")
        anime("Clearing /Author, /Title, /Keywords, etc.")
        empty_metadata = pikepdf.Dictionary()
        pdf.docinfo = pdf.make_indirect(empty_metadata)

        print("[*] Checking for embedded XMP metadata...")
        anime("Looking for /Metadata stream")
        if "/Metadata" in pdf.Root:
            del pdf.Root["/Metadata"]
            print("[+] XMP metadata removed")
        else:
            print("[=] No XMP metadata found")

        print("[*] Finalizing PDF...")
        anime("Writing clean PDF to disk")
        pdf.save(output_pdf)

    print(f"[✓] Metadata successfully removed and saved to: {output_pdf}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python cleanpdfmeta.py input.pdf output.pdf")
        sys.exit(1)

    metaclean(sys.argv[1], sys.argv[2])
