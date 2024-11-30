import base64
import sys

def decode_signature(signature_value):
    """
    Decodes a Base64-encoded signature value after ensuring proper formatting.
    """
    # Step 1: Remove whitespace and invalid characters
    clean_signature = "".join(signature_value.split())

    # Step 2: Ensure length is a multiple of 4 by adding padding ('=')
    while len(clean_signature) % 4 != 0:
        clean_signature += "="

    # Step 3: Decode Base64
    try:
        decoded_signature = base64.b64decode(clean_signature).decode('utf-8')
        return decoded_signature
    except Exception as e:
        print(f"Decoding failed: {e}")
        sys.exit(1)

def encode_signature(decoded_signature):
    """
    Encodes a string back to Base64.
    """
    try:
        return base64.b64encode(decoded_signature.encode('utf-8')).decode('utf-8')
    except Exception as e:
        print(f"Encoding failed: {e}")
        sys.exit(1)

def read_signature_from_file(file_path):
    """
    Reads the signature value from a file.
    """
    try:
        with open(file_path, "r") as file:
            return file.read()
    except Exception as e:
        print(f"Failed to read file: {e}")
        sys.exit(1)

def replace_string(decoded_signature, old_string, new_string):
    """
    Replaces a specific string in the decoded signature.
    """
    return decoded_signature.replace(old_string, new_string)

# Entry point
if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python decode.py <file_path> <old_string> <new_string>")
        sys.exit(1)

    file_path = sys.argv[1]
    old_string = sys.argv[2]
    new_string = sys.argv[3]

    # Read, decode, replace, and encode the signature
    signature_value = read_signature_from_file(file_path)
    decoded_signature = decode_signature(signature_value)
    modified_signature = replace_string(decoded_signature, old_string, new_string)
    encoded_signature = encode_signature(modified_signature)

    print("Modified Base64-encoded Signature:", encoded_signature)
