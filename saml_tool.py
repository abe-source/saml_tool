import base64
import sys
import argparse
import re

def decode_base64_data(signature_value):
    """Decodes Base64-encoded data into raw bytes."""
    clean_signature = "".join(signature_value.split())
    while len(clean_signature) % 4 != 0:
        clean_signature += "="
    try:
        return base64.b64decode(clean_signature)
    except Exception as e:
        raise ValueError(f"Decoding failed: {e}")

def find_emails(data):
    """Finds and prints all email addresses in the given data."""
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    emails = re.findall(email_pattern, data)
    if emails:
        print("Extracted Emails:")
        for email in emails:
            print(email)
    else:
        print("No emails found.")

def extract_and_process_data(decoded_data):
    """Attempts to extract email information from any decoded data."""
    for encoding in ['utf-8', 'iso-8859-1']:
        try:
            print(f"Trying to decode with encoding: {encoding}")
            text_data = decoded_data.decode(encoding)
            find_emails(text_data)
            break  # Exit if successful
        except UnicodeDecodeError:
            continue
    else:
        print("Failed to decode the data with available encodings.")

def modify_xml_with_replacement(decoded_data, old_string, new_string):
    """Replaces a specific string within the XML."""
    for encoding in ['utf-8', 'iso-8859-1']:
        try:
            text_data = decoded_data.decode(encoding)
            modified_data = text_data.replace(old_string, new_string)
            return modified_data.encode(encoding)
        except UnicodeDecodeError:
            continue
    raise ValueError("Failed to replace string in data")

def strip_signature_value(decoded_data):
    """Strips and encodes the content between <ds:SignatureValue> tags."""
    for encoding in ['utf-8', 'iso-8859-1']:
        try:
            text_data = decoded_data.decode(encoding)
            stripped_data = re.sub(r'(<ds:SignatureValue>).*?(</ds:SignatureValue>)', r'\1\2', text_data, flags=re.DOTALL)
            return stripped_data.encode(encoding)
        except UnicodeDecodeError:
            continue
    raise ValueError("Failed to strip signature value in data")

def encode_to_base64(data):
    """Encodes data to Base64."""
    return base64.b64encode(data).decode('utf-8')

def parse_arguments():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description="Process SAML XML data.")
    parser.add_argument('file_path', help="Path to the file containing the Base64-encoded SAML data")
    parser.add_argument('--extract', action='store_true', help="Extract emails or NameID from the SAML assertion")
    parser.add_argument('--replace', nargs=2, metavar=('old_string', 'new_string'), help="Replace old_string with new_string in the XML")
    parser.add_argument('--strip-signature-value', action='store_true', help="Decode then strip value between <ds:SignatureValue> tags and encode it back")
    return parser.parse_args()

def main():
    args = parse_arguments()

    try:
        with open(args.file_path, "r") as file:
            signature_value = file.read().strip()

        decoded_data = decode_base64_data(signature_value)

        # Flag to check if any modification is done
        modified = False

        # Handle signature value stripping
        if args.strip_signature_value:
            decoded_data = strip_signature_value(decoded_data)
            modified = True

        # Handle string replacement
        if args.replace:
            old_string, new_string = args.replace
            decoded_data = modify_xml_with_replacement(decoded_data, old_string, new_string)
            modified = True

        # After modifications, encode the result back to Base64 and print only if modified
        if modified:
            encoded_modified_data = encode_to_base64(decoded_data)
            print("Processed Base64-encoded XML:\n", encoded_modified_data)

        # Handle email extraction
        if args.extract:
            extract_and_process_data(decoded_data)

    except Exception as e:
        print(str(e))
        sys.exit(1)

if __name__ == "__main__":
    main()