
from flask import Flask, render_template, request, make_response, jsonify
from crypto import encrypt_bytes, decrypt_bytes

app = Flask(__name__)

@app.get('/')
def index():
    return render_template('index.html')

@app.post('/api/encrypt-text')
def api_encrypt_text():
    data = request.get_json(force=True, silent=False)
    content = data.get('content','')
    filename = data.get('filename','document.zsl').strip() or 'document.zsl'
    passphrase = data.get('passphrase','')
    if not passphrase:
        return jsonify({'ok': False, 'error': 'Passphrase is required'}), 400
    enc = encrypt_bytes(content.encode('utf-8'), passphrase)
    resp = make_response(enc)
    resp.headers['Content-Type'] = 'application/octet-stream'
    resp.headers['Content-Disposition'] = f'attachment; filename="{filename if filename.endswith(".zsl") else filename + ".zsl"}"'
    return resp

@app.post('/api/decrypt-file')
def api_decrypt_file():
    if 'file' not in request.files:
        return jsonify({'ok': False, 'error': 'No file provided'}), 400
    f = request.files['file']
    passphrase = request.form.get('passphrase','')
    if not passphrase:
        return jsonify({'ok': False, 'error': 'Passphrase is required'}), 400
    blob = f.read()
    try:
        pt = decrypt_bytes(blob, passphrase)
        try:
            text = pt.decode('utf-8')
        except UnicodeDecodeError:
            text = pt.decode('latin-1')
        return jsonify({'ok': True, 'text': text})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
