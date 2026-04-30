#import out ingestion values
from Ingestion import database
from datetime import datetime

# brute map for  brute force detecction and 
brute_map = {}
detection = []

# data entry to the hashmap for detection
for entry in database:
    if entry.ip not in brute_map:
        brute_map[entry.ip] = [entry.timestamp, 1, entry.timestamp, entry.status_code, entry.user_agent]
    else:
        brute_map[entry.ip][1] += 1
        brute_map[entry.ip][2] =  entry.timestamp

# brute force detection
for ip, data in brute_map.items():
    first_seen, count, last_seen, code, agent = data
    duration = (last_seen - first_seen).total_seconds()
    if count > 5 and duration <= 60 and code == "401":
        print(f"[!] ALERT: {ip} flagged for Brute Force.")
        print(f"    Attempts: {count} in {duration:.2f}s with Code: {code}")
        print("_"*40)
    


# Nikto detection
for item in database:
    if item.user_agent == 'sqlmap/1.7.8' or item.user_agent == "Nikto/2.1.6":
        print(f"ALERT: {item.ip} Flagged for{item.user_agent}\n")
        print("_"*40)
        detection.append([item.ip, item.user_agent, item.http_method, item.timestamp, "Nikto"])

        

# SQLI detection
for item in database:
    if item.check_sqli == True:
        print(f"ALERT: {item.ip} Flagged for SQL Injection\n")
        print("_"*40)
        detection.append([item.ip, item.user_agent, item.http_method, item.timestamp, "SQLI"])

# directory traversals 

for item in database:
    if item.check_directory_traversals == True:
        print(f"ALERT: {item.ip} Flagged for Directory Traversals\n")
        print("_"*40)
        detection.append([item.ip, item.user_agent, item.http_method, item.timestamp, "Traversal"])





    
   

            

