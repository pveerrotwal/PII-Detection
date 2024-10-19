import json
from presidio_analyzer import AnalyzerEngine
from Crypto.Cipher import AES
from Crypto.Util import Padding
import tink
import tink_fpe
import base64
import os

analyzer = AnalyzerEngine()

tink_fpe.register()
key_template = tink_fpe.fpe_key_templates.FPE_FF31_256_ALPHANUMERIC
keyset_handle = tink.new_keyset_handle(key_template)
fpe = keyset_handle.primitive(tink_fpe.Fpe)

ENCRYPTION_KEY = b'0123456789abcdef'

def fpe_encrypt(value):
   
    iv = os.urandom(AES.block_size)
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv)

    padded_value = Padding.pad(value.encode(), AES.block_size)
    encrypted_value = cipher.encrypt(padded_value)

    return base64.b64encode(iv + encrypted_value).decode('utf-8')

def detect_and_pseudonymize_pii(text):
    results = analyzer.analyze(text=text, entities=[], language='en')

    if results:
        print("\nIdentified PII in the text:")
        for result in results:
            original_value = text[result.start:result.end]
            print(f"- {result.entity_type}: {original_value}")
    else:
        print("\nNo PII identified.")

    pseudonymized_text = text
    pii_mapping = {}
    for result in results:
        original_value = text[result.start:result.end]

       
        pseudonymized_value = fpe_encrypt(original_value)

        pii_mapping[original_value] = pseudonymized_value
        pseudonymized_text = pseudonymized_text.replace(original_value, pseudonymized_value)

    return pseudonymized_text, pii_mapping

def pseudonymize_json(json_data):
    if isinstance(json_data, dict):
        for key, value in json_data.items():
            json_data[key] = pseudonymize_json(value)
    elif isinstance(json_data, list):
        json_data = [pseudonymize_json(item) for item in json_data]
    elif isinstance(json_data, str):
        pseudonymized_text, _ = detect_and_pseudonymize_pii(json_data)
        return pseudonymized_text
    return json_data

def load_json_file(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def save_pseudonymized_json(file_path, data):
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)

def main():
    file_path = input("Enter the path of the JSON file: ")
    json_data = load_json_file(file_path)

    pseudonymized_data = pseudonymize_json(json_data)

    output_file_path = file_path.replace('.json', '_encrypted_data.json')
    save_pseudonymized_json(output_file_path, pseudonymized_data)

    print(f"\nPseudonymized JSON saved to: {output_file_path}")

if __name__ == "__main__":
    main()
