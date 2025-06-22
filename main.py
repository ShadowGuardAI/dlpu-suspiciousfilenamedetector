import argparse
import os
import re
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SuspiciousFilenameDetector:
    """
    Analyzes filenames in a directory and flags files with names that resemble sensitive data.
    """

    def __init__(self, keywords=None):
        """
        Initializes the SuspiciousFilenameDetector with a list of keywords.

        Args:
            keywords (list, optional): A list of keywords to search for in filenames. Defaults to None.
        """
        if keywords is None:
            self.keywords = ['SSN', 'creditcard', 'confidential', 'secret', 'password', 'api_key', 'apikey'] #added more keywords
        else:
            self.keywords = keywords
        self.sensitive_files = []

    def analyze_directory(self, directory):
        """
        Analyzes all files within a given directory for potentially sensitive filenames.

        Args:
            directory (str): The path to the directory to analyze.
        """
        if not os.path.isdir(directory):
            raise ValueError(f"Invalid directory: {directory}") # Added error handling for invalid directory

        try:
            for filename in os.listdir(directory):
                filepath = os.path.join(directory, filename)
                if os.path.isfile(filepath):
                    self.analyze_filename(filepath)  # Using filepath instead of filename
        except OSError as e:
            logging.error(f"Error accessing directory {directory}: {e}") # Added logging for directory access error
            raise

    def analyze_filename(self, filepath):
        """
        Analyzes a single filename to determine if it contains any suspicious keywords.

        Args:
            filepath (str): The full path to the file to analyze.
        """
        filename = os.path.basename(filepath)  # Extract the filename from the path

        for keyword in self.keywords:
            try:
                pattern = r'\b' + re.escape(keyword) + r'\b'  # Use word boundaries and escape keyword
                if re.search(pattern, filename, re.IGNORECASE): # Case-insensitive search
                    self.sensitive_files.append(filepath) # Append full path to sensitive files
                    logging.warning(f"Potential sensitive filename found: {filepath} (Keyword: {keyword})")
                    break  # No need to check other keywords if one is found

            except re.error as e:
                logging.error(f"Regex error for keyword '{keyword}': {e}") # Added logging for regex errors


    def generate_report(self):
        """
        Generates a report of potentially sensitive files found.

        Returns:
            list: A list of strings, where each string is the path to a sensitive file.
        """
        return self.sensitive_files

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: An argument parser object.
    """
    parser = argparse.ArgumentParser(description='Analyze filenames for potentially sensitive information.')
    parser.add_argument('directory', help='The directory to analyze.')
    parser.add_argument('-k', '--keywords', nargs='+', help='Custom keywords to search for.', required=False)
    parser.add_argument('-o', '--output', help='Output file for report (optional).', required=False)

    return parser


def main():
    """
    Main function to run the filename analyzer.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    directory = args.directory

    if not os.path.exists(directory):
        print(f"Error: Directory '{directory}' does not exist.")
        sys.exit(1)

    try:
        # Input validation
        if not isinstance(directory, str):
            raise TypeError("Directory must be a string.")

        if args.keywords:
            if not all(isinstance(keyword, str) for keyword in args.keywords):
                raise TypeError("Keywords must be strings.")
            analyzer = SuspiciousFilenameDetector(args.keywords) #custom keywords
        else:
            analyzer = SuspiciousFilenameDetector()

        analyzer.analyze_directory(directory)
        report = analyzer.generate_report()


        if args.output:
            try:
                with open(args.output, 'w') as f:
                    for filename in report:
                        f.write(filename + '\n')
                print(f"Report saved to {args.output}")

            except IOError as e:
                logging.error(f"Error writing to output file {args.output}: {e}")
                print(f"Error: Could not write report to {args.output}") #Added user-friendly message
                sys.exit(1)
        else:
            if report:
                print("Potentially sensitive files found:")
                for filename in report:
                    print(filename)
            else:
                print("No potentially sensitive files found.")

    except ValueError as e:
        logging.error(e)
        print(f"Error: {e}") # User-friendly error message
        sys.exit(1)
    except TypeError as e:
        logging.error(e)
        print(f"Error: {e}")
        sys.exit(1)

    except Exception as e: #General Exception
        logging.exception("An unexpected error occurred:")
        print("An unexpected error occurred. See the logs for details.")
        sys.exit(1)


if __name__ == "__main__":
    # Usage examples:
    # 1. Analyze the current directory: python main.py .
    # 2. Analyze a specific directory: python main.py /path/to/directory
    # 3. Analyze a directory with custom keywords: python main.py /path/to/directory -k SSN creditcard secret
    # 4. Analyze a directory and save the report to a file: python main.py /path/to/directory -o report.txt
    main()