Log File Analysis Project
This project processes and analyzes a server log file (sample.log) to extract meaningful insights. The program is written in Python and generates the following outputs:

Requests per IP Address: A count of the total requests made by each IP address.
Most Frequently Accessed Endpoint: The endpoint that received the highest number of requests.
Suspicious Activity Detection: Identification of IP addresses with repeated failed login attempts.
Features
Reads log data from a file named sample.log.
Analyzes HTTP requests and categorizes them by IP address and endpoints.
Detects suspicious activities based on repeated failed login attempts.
Outputs results both to the console and a CSV file (log_analysis_results.csv) for easy reference.
File Structure
main.py: The Python script containing the log analysis code.
sample.log: Sample log file for testing the program.
log_analysis_results.csv: Generated output file with analysis results.
Requirements
Python 3.6+
Required libraries: csv and collections (built-in modules).
How to Run
Clone this repository:
bash
Copy code
git clone https://github.com/saurabhsingh6409/log_project.git
cd folder

Run the script:
bash
Copy code
python main.py  
Check the console for the summary or open log_analysis_results.csv for detailed results.

Console Output:
![image](https://github.com/user-attachments/assets/0473c029-214f-41b0-bb07-3d04b30bb0f0)
![image](https://github.com/user-attachments/assets/040a943f-8985-4a98-b0c1-6c7fb8e74fbd)
![image](https://github.com/user-attachments/assets/2613a0d8-0899-4a5d-9098-eec1ceac728e)



Summary of requests by IP address, most accessed endpoint, and suspicious activities.
CSV File:
A detailed report saved as log_analysis_results.csv.
Contact
For any issues or questions, feel free to contact me at saurabhk.ec.21@nitj.ac.in.

