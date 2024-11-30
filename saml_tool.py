import base64
import sys
import argparse
import xml.etree.ElementTree as ET
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

def parse_xml(xml_data, encoding='utf-8'):
    """Parses XML data and extracts SAML information."""
    try:
        root = ET.fromstring(xml_data)
        for elem in root.iter():
            if 'NameID' in elem.tag or 'Email' in elem.tag:
                print(f"Found potential email or ID information: {elem.text}")
    except ET.ParseError as e:
        # Log where parsing failed
        print(f"XML parsing failed: {e}")

def extract_and_parse_saml(decoded_data):
    """Attempts to extract email information from SAML XML."""
    for encoding in ['utf-8', 'iso-8859-1']:
        try:
            print(f"Trying to decode with encoding: {encoding}")
            xml_data = decoded_data.decode(encoding)
            parse_xml(xml_data)
            return  # Exit if successful
        except UnicodeDecodeError:
            continue
    print("Failed to decode the data with available encodings.")

def replace_string_in_xml(decoded_data, old_string, new_string):
    """Replaces a specific string within the XML."""
    for encoding in ['utf-8', 'iso-8859-1']:
        try:
            xml_data = decoded_data.decode(encoding)
            modified_xml_data = xml_data.replace(old_string, new_string)
            return modified_xml_data.encode(encoding)
        except UnicodeDecodeError:
            continue
    raise ValueError("Failed to replace string in data")

def strip_signature_value(decoded_data):
    """Strips and encodes the content between <ds:SignatureValue> tags."""
    for encoding in ['utf-8', 'iso-8859-1']:
        try:
            text_data = decoded_data.decode(encoding)
            stripped_data = re.sub(r'<ds:SignatureValue>.*?</ds:SignatureValue>', '<ds:SignatureValue></ds:SignatureValue>', text_data, flags=re.DOTALL)
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
    parser.add_argument('--strip-signature-value', action='store_true', help="Decode then strip value in between <ds:SignatureValue> and encode ir back")
    return parser.parse_args()

def main():
    args = parse_arguments()

    try:
        with open(args.file_path, "r") as file:
            signature_value = file.read().strip()

        decoded_data = decode_base64_data(signature_value)

        if args.extract:
            extract_and_parse_saml(decoded_data)

        if args.replace:
            old_string, new_string = args.replace
            modified_data = replace_string_in_xml(decoded_data, old_string, new_string)
            encoded_modified_data = encode_to_base64(modified_data)
            print("Modified Base64-encoded XML:\n", encoded_modified_data)

        if args.strip_signature_value:
            stripped_data = strip_signature_value(decoded_data)
            encoded_stripped_data = encode_to_base64(stripped_data)
            print("Stripped and encoded Base64-encoded XML:\n", encoded_stripped_data)

    except Exception as e:
        print(str(e))
        sys.exit(1)

if __name__ == "__main__":
    main()