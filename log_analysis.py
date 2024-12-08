
import re
import csv
from collections import Counter

# Log parsing function
def parse_logs(log_file):
    ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'  # Extract IP addresses
    endpoint_pattern = r'"(?:GET|POST) (/[^ ]*)'  # Extract endpoints
    failed_login_pattern = r'"POST /login HTTP/1.1" 401'  # Detect failed login attempts

    ip_addresses = []
    endpoints = []
    failed_logins = []

    with open(log_file, 'r') as file:
        for line in file:
            ip_match = re.search(ip_pattern, line)
            endpoint_match = re.search(endpoint_pattern, line)

            if ip_match:
                ip_addresses.append(ip_match.group(1))
            if endpoint_match:
                endpoints.append(endpoint_match.group(1))
            if failed_login_pattern in line:
                ip_failed_login_match = re.search(ip_pattern, line)
                if ip_failed_login_match:
                    failed_logins.append(ip_failed_login_match.group(1))

    return ip_addresses, endpoints, failed_logins

# Analysis and CSV writing function
def analyze_logs(log_file, output_file):
    ip_addresses, endpoints, failed_logins = parse_logs(log_file)

    # Count occurrences
    ip_counts = Counter(ip_addresses)
    endpoint_counts = Counter(endpoints)
    failed_login_counts = Counter(failed_logins)

    # Determine most accessed endpoint
    most_accessed_endpoint = max(endpoint_counts.items(), key=lambda x: x[1], default=("None", 0))

    # Identify suspicious IPs (more than 3 failed login attempts)
    suspicious_ips = {ip: count for ip, count in failed_login_counts.items() if count > 3}

    # Console output
    print("Requests per IP Address:")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in ip_counts.most_common():
        print(f"{ip:<20} {count:<15}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    if suspicious_ips:
        print("\nSuspicious Activity Detected:")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count} failed login attempts")
    else:
        print("\nSuspicious Activity Detected:")
        print("No suspicious activity detected.")

    print(f"\nResults saved to {output_file}.")

    # Write results to CSV
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write IP request counts
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.most_common():
            writer.writerow([ip, count])

        # Add a blank row for separation
        writer.writerow([])

        # Write most accessed endpoint
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Add a blank row for separation
        writer.writerow([])

        # Write suspicious activity
        writer.writerow(["Suspicious IP Address", "Failed Login Attempts"])
        if suspicious_ips:
            for ip, count in suspicious_ips.items():
                writer.writerow([ip, count])
        else:
            writer.writerow(["No suspicious activity detected"])

# Main execution
log_file = "sample.log"  # Replace with your log file path
output_file = "log_analysis_result.csv"
analyze_logs(log_file, output_file)
