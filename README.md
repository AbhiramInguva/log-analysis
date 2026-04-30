# Log Analyzer / Threat Hunter

A Python-based log analysis tool that ingests Apache access logs,
detects attack patterns, and generates a visual HTML threat report.

## Detection Rules
- Brute Force (count + time window)
- SQL Injection
- Directory Traversal
- Scanner User Agents (sqlmap, Nikto)

## Usage
python Ingestion.py
python Detection.py
python reporting.py

## Output
Generates report.html with embedded charts and full alert details.
