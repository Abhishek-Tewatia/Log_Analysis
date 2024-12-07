Log Analysis Script
Description
This Python script analyzes server log files to extract and summarize useful information such as:
    The number of requests per IP address.
    The most frequently accessed endpoints.
    Suspicious activity based on failed login attempts (e.g., status code 401 or "Invalid credentials" in the message).

The script processes the log data and outputs the results to both the console and a CSV file.
Requirements
    Python 3.x
    No external libraries are required as this script uses built-in Python libraries (re, csv, collections).

Files
    script.py – The main Python script that analyzes the log data.
    sample.log – A sample log file (replace with your actual log file).
    log_analysis_results.csv – The output CSV file where the analysis results are saved.

Usage
    Place your server log file (e.g., sample.log) in the same directory as the script.
    Edit the file_path variable in the script to point to your log file (if it’s not named sample.log).
    Run the script:
    python script.py in terminal.
    The results will be printed to the console and saved to a file called log_analysis_results.csv.

Output
The script generates a CSV file named log_analysis_results.csv with the following analysis:
    Requests per IP - The total number of requests made by each IP address.
    Most Frequently Accessed Endpoint - The endpoint that was accessed the most.
    Suspicious Activity - A list of IP addresses that have failed login attempts (status code 401 or a message containing "Invalid credentials").
