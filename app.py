from flask import Flask, render_template, request, jsonify
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import os

app = Flask(__name__)


# ════════════════════════════════════════════
#  AES ENCRYPTION (Symmetric)
#  Same key used for encrypt and decrypt
#  Best for: large text, files
# ════════════════════════════════════════════

def aes_encrypt(plaintext: str, key: bytes) -> dict:
    """
    Encrypts text using AES-CBC mode
    Returns: ciphertext, iv, key (all base64 encoded)
    """
    cipher     = AES.new(key, AES.MODE_CBC)
    padded     = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded)

    return {
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "iv":         base64.b64encode(cipher.iv).decode('utf-8'),
        "key":        base64.b64encode(key).decode('utf-8')
    }


def aes_decrypt(ciphertext_b64: str, iv_b64: str, key_b64: str) -> str:
    """
    Decrypts AES-CBC encrypted text
    Returns: original plaintext
    """
    key        = base64.b64decode(key_b64)
    iv         = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher     = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted  = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode('utf-8')


# ════════════════════════════════════════════
#  RSA ENCRYPTION (Asymmetric)
#  Public key = encrypt, Private key = decrypt
#  Best for: short messages, key exchange
# ════════════════════════════════════════════

def generate_rsa_keys() -> tuple:
    """
    Generates RSA 2048-bit public/private key pair
    Returns: (private_key_pem, public_key_pem)
    """
    key         = RSA.generate(2048)
    private_key = key.export_key().decode('utf-8')
    public_key  = key.publickey().export_key().decode('utf-8')
    return private_key, public_key


def rsa_encrypt(plaintext: str, public_key_pem: str) -> str:
    """
    Encrypts text using RSA public key + OAEP padding
    Returns: base64 encoded ciphertext
    """
    key       = RSA.import_key(public_key_pem)
    cipher    = PKCS1_OAEP.new(key)
    encrypted = cipher.encrypt(plaintext.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')


def rsa_decrypt(ciphertext_b64: str, private_key_pem: str) -> str:
    """
    Decrypts RSA encrypted text using private key
    Returns: original plaintext
    """
    key       = RSA.import_key(private_key_pem)
    cipher    = PKCS1_OAEP.new(key)
    decrypted = cipher.decrypt(base64.b64decode(ciphertext_b64))
    return decrypted.decode('utf-8')


# ════════════════════════════════════════════
#  FLASK ROUTES
# ════════════════════════════════════════════

@app.route('/')
def index():
    return render_template('index.html')


# ── AES Encrypt API ──
@app.route('/aes/encrypt', methods=['POST'])
def api_aes_encrypt():
    try:
        data      = request.json
        plaintext = data.get('text', '').strip()
        key_bits  = int(data.get('keySize', 256))

        if not plaintext:
            return jsonify({"error": "Text cannot be empty"}), 400

        key_size = key_bits // 8  # Convert bits to bytes (256 -> 32)
        key      = get_random_bytes(key_size)
        result   = aes_encrypt(plaintext, key)

        return jsonify({
            "success":    True,
            "ciphertext": result['ciphertext'],
            "iv":         result['iv'],
            "key":        result['key'],
            "keySize":    key_bits,
            "mode":       "AES-CBC"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── AES Decrypt API ──
@app.route('/aes/decrypt', methods=['POST'])
def api_aes_decrypt():
    try:
        data       = request.json
        ciphertext = data.get('ciphertext', '').strip()
        iv         = data.get('iv', '').strip()
        key        = data.get('key', '').strip()

        if not all([ciphertext, iv, key]):
            return jsonify({"error": "Ciphertext, IV and Key are all required"}), 400

        plaintext = aes_decrypt(ciphertext, iv, key)
        return jsonify({"success": True, "plaintext": plaintext})

    except Exception as e:
        return jsonify({"error": "Decryption failed — check your key and IV"}), 500


# ── RSA Generate Keys API ──
@app.route('/rsa/generate', methods=['POST'])
def api_rsa_generate():
    try:
        private_key, public_key = generate_rsa_keys()
        return jsonify({
            "success":    True,
            "publicKey":  public_key,
            "privateKey": private_key
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── RSA Encrypt API ──
@app.route('/rsa/encrypt', methods=['POST'])
def api_rsa_encrypt():
    try:
        data       = request.json
        plaintext  = data.get('text', '').strip()
        public_key = data.get('publicKey', '').strip()

        if not plaintext or not public_key:
            return jsonify({"error": "Text and Public Key are required"}), 400

        if len(plaintext) > 190:
            return jsonify({"error": "Text too long for RSA. Max ~190 characters. Use AES for larger data."}), 400

        ciphertext = rsa_encrypt(plaintext, public_key)
        return jsonify({"success": True, "ciphertext": ciphertext})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── RSA Decrypt API ──
@app.route('/rsa/decrypt', methods=['POST'])
def api_rsa_decrypt():
    try:
        data        = request.json
        ciphertext  = data.get('ciphertext', '').strip()
        private_key = data.get('privateKey', '').strip()

        if not ciphertext or not private_key:
            return jsonify({"error": "Ciphertext and Private Key are required"}), 400

        plaintext = rsa_decrypt(ciphertext, private_key)
        return jsonify({"success": True, "plaintext": plaintext})

    except Exception as e:
        return jsonify({"error": "Decryption failed — wrong key or corrupted data"}), 500


# ════════════════════════════════════════════
#  START SERVER
# ════════════════════════════════════════════

if __name__ == '__main__':
    print("\n" + "═" * 50)
    print("    Encryption & Decryption System")
    print("   Open browser: http://localhost:5000")
    print("═" * 50 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=False)
