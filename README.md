# dlpu-SuspiciousFilenameDetector
Analyzes filenames in a directory and flags files with names that resemble sensitive data (e.g., containing 'SSN', 'creditcard', 'confidential') using regular expressions and a configurable keyword list.  Outputs a report of potentially sensitive files. - Focused on Identifies and redacts or flags sensitive data (e.g., email addresses, phone numbers, credit card numbers, API keys, domain names) from text files, logs, or network traffic captures.  Employs regular expressions and contextual analysis to detect potentially leaked information. Supports customizable patterns and sensitivity levels.

## Install
`git clone https://github.com/ShadowGuardAI/dlpu-suspiciousfilenamedetector`

## Usage
`./dlpu-suspiciousfilenamedetector [params]`

## Parameters
- `-h`: Show help message and exit
- `-k`: Custom keywords to search for.
- `-o`: No description provided

## License
Copyright (c) ShadowGuardAI
