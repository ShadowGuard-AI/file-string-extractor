#!/usr/bin/env python3

import argparse
import logging
import os
import re
import sys
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Regex patterns for identifying potential secrets
URL_REGEX = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
API_KEY_REGEX = re.compile(r'[a-zA-Z0-9]{32,}')  # Simplified, needs refinement
CREDIT_CARD_REGEX = re.compile(r'^(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11})$') # Basic CC check


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='Extracts strings from a file and flags potential secrets.')
    parser.add_argument('filepath', type=str, help='Path to the file to analyze.')
    parser.add_argument('-o', '--output', type=str, help='Path to the output file (optional).', default=None)
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging.')
    parser.add_argument('-e', '--encoding', type=str, default='utf-8', help='File encoding (default: utf-8).')
    return parser.parse_args()


def extract_strings(filepath, encoding='utf-8'):
    """
    Extracts printable strings from a file.

    Args:
        filepath (str): The path to the file.
        encoding (str): The encoding of the file (default: utf-8).

    Returns:
        list: A list of printable strings found in the file.  Returns None if there's an error reading the file.
    """
    try:
        with open(filepath, 'rb') as f:  # Open in binary mode for better compatibility
            content = f.read()
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return None
    except Exception as e:
        logging.error(f"Error reading file {filepath}: {e}")
        return None

    try:
        # Attempt decoding with specified encoding. Handle errors gracefully.
        text = content.decode(encoding, errors='ignore') # 'ignore' replaces undecodable chars
    except UnicodeDecodeError as e:
        logging.warning(f"UnicodeDecodeError with encoding '{encoding}': {e}. Trying latin-1...")
        try:
            text = content.decode('latin-1', errors='ignore') # Fallback to latin-1 for wider compatibility
        except UnicodeDecodeError as e:
            logging.error(f"Failed to decode file: {e}")
            return None


    strings = re.findall(r'[ -~]{4,}', text)  # Find strings of at least 4 printable characters
    return strings


def identify_secrets(strings):
    """
    Identifies potential URLs, email addresses, and API keys within a list of strings.

    Args:
        strings (list): A list of strings to analyze.

    Returns:
        dict: A dictionary containing lists of identified URLs, email addresses, and API keys.
    """
    secrets = {
        'urls': [],
        'emails': [],
        'api_keys': [],
        'credit_cards': []
    }

    for s in strings:
        if URL_REGEX.search(s):
            secrets['urls'].append(s)
        if EMAIL_REGEX.search(s):
            secrets['emails'].append(s)
        if API_KEY_REGEX.search(s):
            secrets['api_keys'].append(s)
        if CREDIT_CARD_REGEX.search(s):
            secrets['credit_cards'].append(s)

    return secrets


def write_output(strings, secrets, output_file=None):
    """
    Writes the extracted strings and identified secrets to the console or a file.

    Args:
        strings (list): The list of extracted strings.
        secrets (dict): The dictionary of identified secrets.
        output_file (str, optional): The path to the output file. If None, output is printed to the console.
    """
    output = "Extracted Strings:\n"
    output += "\n".join(strings)
    output += "\n\nIdentified Secrets:\n"
    for key, values in secrets.items():
        if values:
            output += f"\n{key.capitalize()}:\n"
            output += "\n".join(values)

    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(output)
            logging.info(f"Output written to {output_file}")
        except Exception as e:
            logging.error(f"Error writing to file {output_file}: {e}")
    else:
        print(output)


def validate_filepath(filepath):
    """
    Validates that the provided filepath exists.

    Args:
        filepath (str): The path to the file.

    Returns:
        bool: True if the file exists, False otherwise.
    """
    path = Path(filepath)
    if not path.exists():
        logging.error(f"File does not exist: {filepath}")
        return False
    return True


def main():
    """
    Main function to execute the string extraction and secret identification process.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    filepath = args.filepath

    if not validate_filepath(filepath):
        sys.exit(1) # Exit with error code

    strings = extract_strings(filepath, args.encoding)

    if strings is None:
        sys.exit(1) # Exit with error code

    secrets = identify_secrets(strings)

    write_output(strings, secrets, args.output)


if __name__ == "__main__":
    main()

"""
Usage Examples:

1.  Run the script with a file:
    python file-string-extractor.py myfile.txt

2.  Run the script with a file and specify an output file:
    python file-string-extractor.py myfile.txt -o output.txt

3.  Run the script with verbose logging:
    python file-string-extractor.py myfile.txt -v

4. Run the script with a specific encoding:
    python file-string-extractor.py myfile.txt -e latin-1

5.  Handle file not found gracefully:
    python file-string-extractor.py non_existent_file.txt

6. Check for secrets and output to a file:
   python file-string-extractor.py input.txt -o secrets.txt
"""