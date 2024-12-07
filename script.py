import re
import csv
from collections import Counter

def analyze_log(file_path):
    log_data = []

    # Regular expression for matching pattern for IP address, endpoints and status_codes
    log_pattern = r'(?P<ip_address>\d+\.\d+\.\d+\.\d+) - - \[.*\] "(?P<method>GET|POST) (?P<endpoint>/\S+)' \
                  r' .* (?P<status_code>\d{3}) \d+(?: "(?P<message>.*?)")?\s*$'

    # Reading log file
    with open(file_path, 'r') as f:
        for line in f:
            match = re.search(log_pattern, line)
            if match:
                ip_address = match.group('ip_address')
                endpoint = match.group('endpoint')
                status_code = match.group('status_code')
                message = match.group('message') if match.group('message') else ''

                # Store the extracted data in a dictionary
                log_data.append({
                    'ip_address': ip_address,
                    'endpoint': endpoint,
                    'status_code': status_code,
                    'message': message
                })
            else:
                # Handling case where patten not matching
                print(f"Line does not match: {line}")

    return log_data

def analyze_log_data(log_entries):
    # Counting requests per IP address
    ip_random = Counter(entry['ip_address'] for entry in log_entries)
    ip_count = ip_random.most_common()  
    
    # Counting most accessed endpoints
    endpoint_random = Counter(entry['endpoint'] for entry in log_entries)
    endpoint_count = endpoint_random.most_common()
    
    # Identifying suspicious activity (failed logins, e.g., status_code 401 or "Invalid credentials")
    suspicious_activity = Counter()
    for entry in log_entries:
        if entry['status_code'] == '401' or 'Invalid credentials' in entry['message']:
            suspicious_activity[entry['ip_address']] += 1

    # Activity Threshold Check
    if suspicious_activity and max(suspicious_activity.values()) >= 10:
        return ip_count, endpoint_count, suspicious_activity
    else:
        return ip_count, endpoint_count, {}

def save_to_csv(ip_count, endpoint_count, suspicious_activity, output_file="log_analysis_results.csv"):
    # Writing to CSV
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write "Requests per IP" and print to terminal
        writer.writerow(["Requests per IP:"])
        writer.writerow(["IP Address", "Request Count"])
        print("Requests per IP:")
        print(f"{'IP Address':<15} {'Request Count'}")
        for ip, count in ip_count:
            writer.writerow([ip, count])
            print(f"{ip:<15} {count}")

        # Write an empty row for separation
        writer.writerow([])
        print("\nMost Frequently Accessed Endpoint:")

        # Write "Most Accessed Endpoint"
        max_count = max(count for endpoint, count in endpoint_count)

        # Filter out the endpoints with the highest count
        highest_endpoints = [endpoint for endpoint, count in endpoint_count if count == max_count]

        # Write the data to the same CSV file and print to terminal
        writer.writerow(["Most Frequently Accessed Endpoint:"])
        writer.writerow(["Endpoint", "Access Count"])
        print(f"{'Endpoint':<25} {'Access Count'}")
        for endpoint in highest_endpoints:
            writer.writerow([endpoint, max_count])
            print(f"{endpoint:<25} {max_count}")

        # Write an empty row for separation
        writer.writerow([])

        if suspicious_activity:
            print("\nSuspicious Activity Detected:")

            # Write "Suspicious Activity"
            writer.writerow(["Suspicious Activity Detected:"])
            writer.writerow(["IP Address", "Failed Login Attempts"])
            print(f"{'IP Address':<15} {'Failed Login Attempts'}")
            for ip, count in suspicious_activity.items():
                if count >= 10:
                    writer.writerow([ip, count])
                    print(f"{ip:<15} {count}")
        else:
            writer.writerow(["No Suspicious Activity Detected:"])
            print("No Suspicious Activity Detected")

def main():
    file_path = "sample.log"
    log_entries = analyze_log(file_path)

    # Analyze the log data
    ip_count, endpoint_count, suspicious_activity = analyze_log_data(log_entries)

    # Save the results to a CSV file
    save_to_csv(ip_count, endpoint_count, suspicious_activity)

    print("Log analysis results saved to log_analysis_results.csv")

if __name__ == "__main__":
    main()