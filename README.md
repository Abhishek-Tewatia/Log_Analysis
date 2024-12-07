# Log Analysis Script

## Description
This Python script analyzes server log files to extract and summarize useful information such as:
- The number of requests per IP address.
- The most frequently accessed endpoints.
- Suspicious activity based on failed login attempts (e.g., status code 401 or "Invalid credentials" in the message).

The script processes the log data and outputs the results to both the console and a CSV file.

## Requirements
- Python 3.x
- No external libraries are required. The script uses built-in Python libraries:
  - `re` (Regular Expressions)
  - `csv` (CSV handling)
  - `collections` (Data structures for efficient data management)

## Files
- `script.py`: The main Python script that analyzes the log data.
- `sample.log`: A sample log file (replace with your actual log file).
- `log_analysis_results.csv`: The output CSV file where the analysis results are saved.

## Usage

1. **Place your server log file** (e.g., `sample.log`) in the same directory as the script.
2. **Edit the `file_path` variable** in `script.py` to point to your actual log file if it's not named `sample.log`.
3. Run the script with the following command in your terminal:
   ```bash
   python script.py
