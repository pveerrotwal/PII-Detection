import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import tink
import tink_fpe
import re

tink_fpe.register()
key_template = tink_fpe.fpe_key_templates.FPE_FF31_256_ALPHANUMERIC
keyset_handle = tink.new_keyset_handle(key_template)
fpe = keyset_handle.primitive(tink_fpe.Fpe)

def decrypt_aes(ciphertext, key):
    try:
        ciphertext_bytes = base64.b64decode(ciphertext)
        iv = ciphertext_bytes[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext_bytes[AES.block_size:]), AES.block_size)
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"Decryption failed for value: {ciphertext}, error: {e}")
        return None

def is_base64_encoded(s):
    if isinstance(s, str):
        if len(s) % 4 == 0 and re.match(r'^[A-Za-z0-9+/]*={0,2}$', s):
            return True
    return False

def decrypt_json_data(json_data, key):
    decrypted_data = {}
    for k, value in json_data.items():
        if isinstance(value, str):
            # Handle case where multiple encrypted segments are concatenated with commas
            base64_values = value.split(', ')
            decrypted_values = []
            
            for base64_value in base64_values:
                if is_base64_encoded(base64_value):
                    decrypted_result = decrypt_aes(base64_value.strip(), key)
                    if decrypted_result:
                        decrypted_values.append(decrypted_result)
                    else:
                        decrypted_values.append(base64_value)  # In case decryption fails
                else:
                    decrypted_values.append(base64_value)  # Keep the original value if not encrypted

            decrypted_data[k] = ', '.join(decrypted_values)  # Join decrypted parts
        elif isinstance(value, list):
            decrypted_data[k] = [decrypt_json_data(item, key) if isinstance(item, dict) else item for item in value]
        elif isinstance(value, dict):
            decrypted_data[k] = decrypt_json_data(value, key)
        else:
            decrypted_data[k] = value
    return decrypted_data

def main():
    input_path = input("Enter the path of the pseudonymized JSON file: ")
    key = b'0123456789abcdef' 
    
    with open(input_path, 'r') as file:
        json_data = json.load(file)
        
    decrypted_data = decrypt_json_data(json_data, key)
    
    output_path = 'original_data.json'
    with open(output_path, 'w') as outfile:
        json.dump(decrypted_data, outfile, indent=4)
    
    print(f"Decrypted data saved to {output_path}")

if __name__ == "__main__":
    main()
