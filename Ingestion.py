import re
from datetime import datetime


# 1. Define the blueprint for a single log entry
class Ingestion:
    def __init__(self, line):

        self.ip = self.extract_ip(line)
        self.timestamp = self.extract_timestamp(line)
        self.http_method = self.extract_http_method(line)
        self.status_code = self.extract_status(line)
        self.response_size = self.extract_response_size(line)
        self.user_agent = self.extract_user_agent(line)
        self.check_sqli = self.extract_SQLI(line)
        self.check_directory_traversals = self.extract_traversal(line)

    def extract_ip(self, line):
        pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        match = re.search(pattern, line)
        return match.group() if match else "No IP"

    def extract_timestamp(self, line):
        # Using regex lookarounds to capture only the Date:Time
        pattern = r"(?<=\[)\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?=\s+[+-]\d{4}\])"
        match = re.search(pattern, line)
        
        if match:
            timestamp_string = match.group()
            date_format = "%d/%b/%Y:%H:%M:%S"
            # Return the object immediately once successful
            return datetime.strptime(timestamp_string, date_format)
        
        # If no match is found, return None (cleaner for data analysis)
        return None
    
    def extract_http_method(self, line):
        pattern = r"\b(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|TRACE|CONNECT)\b"
        match = re.search(pattern, line)
        return match.group() if match else "No HTTP Method"
    
    def extract_status(self, line):
        pattern = r'"\s+([1-5]\d{2})\s+'
        match = re.search(pattern, line)
        return match.group(1) if match else "No Status Code"
    
    def extract_response_size(self, line):
        pattern = r'"\s+\d{3}\s+(\d+|-)'
        match = re.search(pattern, line)
        
        return match.group(1) if match else "No Response Size"
    
    def extract_user_agent(self, line):
        pattern = r'"([^"]+)"\s*$'
        match = re.search(pattern, line)
        return match.group(1) if match else "No User Agent"
        
    def extract_SQLI(self, line):
        pattern = r"(?i)(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|ALTER|OR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|--|#|\/\*)"
        match = re.search(pattern, line)
        return True if match else False
    def extract_traversal(self,line):
        pattern = r"(\.\.\/|\.\.\\|\/etc\/passwd|\/windows\/win\.ini|\/bin\/sh)"
        match = re.search(pattern, line)
        return True if match else False



database = []

# 3. Read the file
with open('/Users/abhiraminguva/Code/sample_access.log', 'r') as log:
    for line in log:
        if line.startswith('#') or line.strip() == "":
            continue
            
        # Create a new Ingestion object for this line
        record = Ingestion(line)
        
        # Save the whole object into our database
        database.append(record)

# --- At the bottom of ingestion.py ---

def load_database():
    database = []
    file_path = '/Users/abhiraminguva/Code/sample_access.log'
    
    with open(file_path, 'r') as log:
        for line in log:
            if line.startswith('#') or line.strip() == "":
                continue
            database.append(Ingestion(line)) # Creating the object
            
    return database 

if __name__ == '__main__':
    for entry in database:
        print(f"IP: {entry.ip}")
        print(f"Time: {entry.timestamp}")
        print(f"Method: {entry.http_method}")
        print(f"Status: {entry.status_code}")
        print(f"Size: {entry.response_size}")
        print(f"Agent: {entry.user_agent}")
        print(f"SQLI : {entry.check_sqli}")
        print(f"Directory : {entry.check_directory_traversals}")
        print("-" * 40)