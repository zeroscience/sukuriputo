#!/usr/bin/env python
#
# 2025 (c) Zero Science Lab
#
# Ver: 1.0
#

import sys
import html

def get_html_template(rows):
    lines = [
        '<!DOCTYPE html>',
        '<html lang="en">',
        '<head>',
        '    <meta charset="UTF-8">',
        '    <meta name="viewport" content="width=device-width, initial-scale=1.0">',
        '    <title>Highlighted Code</title>',
        '    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.8.0/styles/atom-one-dark.min.css">',
        '    <style>',
        '        body {',
        '            background: #1e2127;',
        '            color: #abb2bf;',
        '            font-family: \'Courier New\', monospace;',
        '            font-size: 10pt;',
        '            padding: 20px;',
        '            margin: 0;',
        '        }',
        '        table {',
        '             border-collapse: collapse;',
        '             background: #1e2127 !important;',
        '             color: #abb2bf;',
        '             border-spacing: 0;',
        '             width: 100%;',
        '             max-width: 6.5in;',
        '             margin: 0;',
        '        }',
        '        tr {',
        '            margin: 0;',
        '            padding: 0;',
        '        }',
        '        td {',
        '            padding: 0 6px;',
        '            vertical-align: top;',
        '            border: none;',
        '            margin: 0;',
        '            background: #1e2127 !important;',
        '        }',
        '        .line-number {',
        '            background: #1a1d22 !important;',
        '            color: #a5a9b2;',
        '            text-align: right;',
        '            width: 40px;',
        '            user-select: none;',
        '        }',
        '        .code {',
        '            white-space: pre;',
        '            line-height: 1.2;',
        '            background: #1e2127 !important;',
        '        }',
        '        .empty-line {',
        '            height: 1.2em;',
        '            background: #1e2127;',
        '        }',
        '        .hljs-comment { color: #5c6370; }',
        '        .hljs-quote { color: #5c6370; }',
        '        .hljs-keyword { color: #c678dd; }',
        '        .hljs-string { color: #98c379; }',
        '        .hljs-number { color: #d19a66; }',
        '        .hljs-title { color: #61afef; }',
        '        .hljs-name { color: #e06c75; }',
        '    </style>',
        '</head>',
        '<body>',
        '    <table>',
    ]
    lines.append('<tr><td class="empty-line" colspan="2"></td></tr>')
    lines.extend(rows)
    lines.append('<tr><td class="empty-line" colspan="2"></td></tr>')
    lines.extend([
        '    </table>',
        '    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.8.0/highlight.min.js"></script>',
        '    <script>',
        '        document.querySelectorAll(\'.code\').forEach(block => {',
        '            hljs.highlightElement(block);',
        '        });',
        '    </script>',
        '</body>',
        '</html>'
    ])
    return '\n'.join(lines)

def generate_html_page(code, language, start_line, output_file):
    rows = []
    for i, line in enumerate(code.splitlines(), start=start_line):
        escaped_line = html.escape(line)
        rows.append(f'<tr><td class="line-number">{i}</td><td class="code language-{language}">{escaped_line}</td></tr>')
    
    html_content = get_html_template(rows)
    
    with open(output_file, 'w', encoding='utf-8') as file:
        file.write(html_content)

def main():
    if len(sys.argv) < 3:
        print("Usage: python codehigh.py <filename> <start_line> [language]")
        sys.exit(1)
    
    filename = sys.argv[1]
    start_line = int(sys.argv[2])
    language = sys.argv[3] if len(sys.argv) > 3 else "text"
    output_file = "high_code.html"
    
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            code = file.read()
        
        generate_html_page(code, language, start_line, output_file)
        print(f"HTML page generated: {output_file}")
        print(f"Code highlighted with line numbers starting from {start_line}")
    
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
    except ValueError:
        print("Error: Start line must be an integer.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
