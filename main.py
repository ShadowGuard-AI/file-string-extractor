#!/usr/bin/env python3

import argparse
import codecs
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
        # errors='ignore' makes the except below unreachable: a decode that
        # drops bad bytes never raises UnicodeDecodeError, so the latin-1
        # fallback is dead code in practice. What actually happens to a file
        # in the wrong encoding is quieter: bytes vanish, and the string
        # search runs over what survives. A UTF-16 file read as UTF-8 loses
        # every second byte's meaning and its strings come out fragmented.
        text = content.decode(encoding, errors='ignore') # 'ignore' replaces undecodable chars
    except UnicodeDecodeError as e:
        logging.warning(f"UnicodeDecodeError with encoding '{encoding}': {e}. Trying latin-1...")
        try:
            text = content.decode('latin-1', errors='ignore') # Fallback to latin-1 for wider compatibility
        except UnicodeDecodeError as e:
            logging.error(f"Failed to decode file: {e}")
            return None


    # Printable means the ASCII range from space to tilde, four or more in
    # a row. Anything outside that range, accented letters included, breaks
    # a string into pieces, and pieces under four characters are dropped.
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
            # The whole containing string is recorded, not just the matched part.
            # A URL inside a long log line puts the entire line in the report,
            # which keeps context and also means the report can carry text nobody
            # classified as sensitive.
            secrets['urls'].append(s)
        if EMAIL_REGEX.search(s):
            secrets['emails'].append(s)
        # The API key pattern is any run of 32 or more letters and digits, so
        # hashes, long words, and base64 fragments all flag. It is a net, not
        # an identifier. The credit card pattern is the opposite shape:
        # anchored to the whole string, so a card number is only flagged when
        # the extracted string is exactly the number and nothing else.
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
            return True
        except Exception as e:
            logging.error(f"Error writing to file {output_file}: {e}")
            return False
    else:
        print(output)
        return True


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

    try:
        codecs.lookup(args.encoding)
    except LookupError:
        logging.error(f"Unknown encoding: {args.encoding}")
        sys.exit(1)

    if not validate_filepath(filepath):
        sys.exit(1) # Exit with error code

    if args.output and Path(args.output).resolve() == Path(filepath).resolve():
        logging.error("Output file is the same as the input file. Refusing to overwrite the input.")
        sys.exit(1)

    strings = extract_strings(filepath, args.encoding)

    if strings is None:
        sys.exit(1) # Exit with error code

    logging.info(f"Extracted {len(strings)} string(s) from {filepath}")

    if len(strings) == 0:
        print("No strings extracted.")
        sys.exit(1)

    secrets = identify_secrets(strings)

    if not write_output(strings, secrets, args.output):
        sys.exit(1)


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