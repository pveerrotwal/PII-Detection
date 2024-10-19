```markdown
# PII Detection and Pseudonymization Project

## Introduction

This project aims to detect Personally Identifiable Information (PII) using **Presidio Analyzer** within a given text or JSON structure and pseudonymize that data using a combination of **Format-Preserving Encryption (FPE)** and **AES (Advanced Encryption Standard)**. The primary objective is to ensure that sensitive information, such as names, addresses, and Social Security Numbers (SSNs), is securely encrypted while maintaining the original format wherever necessary.

## Technologies Used

- **Presidio Analyzer**: A tool developed by Microsoft to analyze and identify PII in text.
- **Tink**: A multi-language library for secure encryption that supports Format-Preserving Encryption.
- **AES**: A symmetric encryption algorithm used for secure data encryption and decryption.

## Procedure

### 1. Detecting PII using Presidio Analyzer

Presidio Analyzer is utilized to identify PII in the input text. Below is an overview of the detection process:

- **Initialize the Analyzer Engine**:
  - Import the necessary library and create an instance of `AnalyzerEngine`.
  - Specify the language of the text (e.g., English).

- **Analyze the Input Text**:
  - Use the `analyze` method of the `AnalyzerEngine` to scan the text for PII.
  - Retrieve and print the identified PII entities (e.g., names, addresses, SSNs).

```python
from presidio_analyzer import AnalyzerEngine

analyzer = AnalyzerEngine()

def detect_and_pseudonymize_pii(text):
    results = analyzer.analyze(text=text, entities=[], language='en')
```

### 2. Pseudonymization using FPE and AES

#### 2.1 Format-Preserving Encryption (FPE)

FPE allows for encrypting data while preserving its original format. In this project, Tink’s FPE capabilities are leveraged. The steps include:

- **Import Tink Libraries**: Import necessary libraries for FPE encryption and decryption.
- **Encrypt and Decrypt**: Create functions to handle encryption using Tink’s FPE mechanism.

```python
from tink import cleartext_key_manager
from tink import fpe

tink_fpe.register()
key_template = tink_fpe.fpe_key_templates.FPE_FF31_256_ALPHANUMERIC
keyset_handle = tink.new_keyset_handle(key_template)
fpe = keyset_handle.primitive(tink_fpe.Fpe)
```

#### 2.2 AES Encryption and Decryption

AES is implemented as an additional layer of encryption for security. The steps for AES encryption and decryption are as follows:

- **Setup AES Key**: Define a fixed encryption key (16 bytes for AES-128).
- **Encrypt the PII**: Use AES in CBC mode to encrypt the identified PII.

```python
from Crypto.Cipher import AES
from Crypto.Util import Padding
import base64
import os

ENCRYPTION_KEY = b'your_key'

def fpe_encrypt(value):
    iv = os.urandom(AES.block_size)
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv)
    padded_value = Padding.pad(value.encode(), AES.block_size)
    encrypted_value = cipher.encrypt(padded_value)
    return base64.b64encode(iv + encrypted_value).decode('utf-8')
```

### 3. Pseudonymizing JSON Data

- **Pseudonymize JSON Objects**: Traverse through the JSON structure and pseudonymize all detected PII in the fields.

```python
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
```

### 4. Running the Program

To run the pseudonymization on a JSON file:

1. Load the JSON file.
2. Pseudonymize the PII detected.
3. Save the pseudonymized JSON to a new file.

```python
def main():
    file_path = input("Enter the path of the JSON file: ")
    json_data = load_json_file(file_path)
    pseudonymized_data = pseudonymize_json(json_data)
    output_file_path = file_path.replace('.json', '_encrypted_data.json')
    save_pseudonymized_json(output_file_path, pseudonymized_data)
    print(f"\nPseudonymized JSON saved to: {output_file_path}")

if __name__ == "__main__":
    main()
```

## Encrypted JSON Example

```json
{
    "company": {
        "name": "Tech Innovators Inc.",
        "founded": "AIGM7DgpmvLtBhCQykdnfB3CGTf/RtfemfIxXDfXpow=",
        "address": "789, KCD+lVXDGioz/MqR5JHQydTwCUA1w+QbsFY+wmbOB8A=, UxiO7iSGxK+fqxv17hJj4Rl2zgSCUDbjm0p7r+FMgpY="
    }
}
```

## Decryption

To reverse the encryption:

```python
def decrypt_aes(ciphertext, key):
    ciphertext_bytes = base64.b64decode(ciphertext)
    iv = ciphertext_bytes[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext_bytes[AES.block_size:]), AES.block_size)
    return decrypted.decode('utf-8')
```

## Conclusion

This project securely pseudonymizes PII data using a combination of **Presidio Analyzer**, **FPE**, and **AES**. The encryption methods used ensure that sensitive information is both protected and retains its original format where needed, making it suitable for environments where format preservation is critical.
```

This README provides a comprehensive overview of the project, outlining the steps for detecting and pseudonymizing PII with detailed code snippets for reference.
