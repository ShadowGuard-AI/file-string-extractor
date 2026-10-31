![Banner](banner.png)

# file-string-extractor
Extracts all printable strings from a file and flags those that resemble URLs, email addresses, or cryptographic keys/secrets, aiding in identifying potentially sensitive or malicious content. - Focused on File operations and analysis

## Install
`git clone https://github.com/ShadowStrikeHQ/file-string-extractor`

## Usage
`./file-string-extractor [params]`

## Parameters
- `-h`: Show help message and exit
- `-o`: Path to the output file. The output path may not be the input file itself: a run whose resolved output path equals the input path is refused and exits 1 before any write.
- `-v`: Enable verbose logging.
- `-e`: File encoding (default: utf-8). An unknown encoding name is reported and the run exits 1.

## Exit codes
Every run logs how many strings were extracted. A run that extracts no strings prints "No strings extracted." and exits 1. A failed output write also exits 1. Exit 0 means strings were extracted and the report was delivered.

## License
Copyright (c) ShadowStrikeHQ
