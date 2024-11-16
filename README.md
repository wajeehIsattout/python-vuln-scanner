
# Vulnerability Scanner

## Overview
This tool is a Python-based vulnerability scanner designed to test web applications for common security issues, including SQL Injection, Cross-Site Scripting (XSS), and Directory Traversal. It scans URLs and form inputs for potential vulnerabilities and outputs a report of any issues found, along with recommended remediation steps.

The tool includes a Docker-based setup for testing against the OWASP Juice Shop, an intentionally vulnerable web application. This Docker setup allows you to safely and conveniently test the scanner's functionality in a controlled environment.

## Features
- **SQL Injection Testing**: Detects potential SQL injection vulnerabilities in URL parameters and forms.
- **Cross-Site Scripting (XSS) Testing**: Identifies possible XSS vulnerabilities by injecting test payloads in URLs and forms.
- **Directory Traversal Testing**: Checks for directory traversal vulnerabilities in URL parameters.
- **Modular Design**: Easily extendable to add more types of vulnerability checks.
- **Reporting**: Generates a JSON report listing vulnerabilities found, affected URLs, payloads used, and suggested remediation.

---

## Docker Environment Setup

This project uses Docker to run OWASP Juice Shop, a vulnerable web application designed for security testing. Running this environment allows you to test the scanner against a live target without any risk to real applications.

### Prerequisites
- **Docker**: [Install Docker](https://docs.docker.com/get-docker/) if it is not already installed on your system.
- **Docker Compose**: Docker Compose is included with Docker Desktop. If using Linux, [install Docker Compose](https://docs.docker.com/compose/install/).

### Setting Up the Environment
1. Clone or download the project repository.
2. Navigate to the `docker_setup` directory where the Docker Compose file is located.
3. Start the Docker environment by running:

   ```bash
   docker-compose up -d
   ```

   This will download and start OWASP Juice Shop, accessible at `http://localhost:3000`.

4. To stop the Docker container, use:

   ```bash
   docker-compose down
   ```

> **NOTE**: Running `docker-compose down` will stop and remove the container, freeing up resources on your system.

---

## Installation and Running the Vulnerability Scanner

1. **Install Required Python Libraries**:
   This tool requires the following Python packages:
   - `requests`
   - `BeautifulSoup4`
   - `termcolor`

   Install these packages by running:

   ```bash
   pip install requests beautifulsoup4 termcolor
   ```

2. **Run the Vulnerability Scanner**:
   With the Docker environment running (if testing against Juice Shop), execute the scanner by specifying the target URL as follows:

   ```bash
   python security_scanner.py -u "http://localhost:3000"
   ```

   **Additional Command-line Options**:
   - `-i` or `--ignore`: Comma-separated URLs to ignore during scanning, (Example usage: preventing the tool from running log out url and loosing session).
   - `-l` or `--login_url`: URL for logging in if authentication is required.
   - `-n` or `--username`: Username for login (if required).
   - `-p` or `--password`: Password for login (if required).

3. **Output**:
   The scanner outputs the results to the console and saves a JSON report (`report.json`) listing any detected vulnerabilities, payloads used, affected URLs, and remediation suggestions.

---

## Types of Vulnerabilities Tested
This scanner checks for the following vulnerabilities:

1. **SQL Injection**:
   - Tries common SQL injection payloads in URLs and form fields to identify potential database query manipulation risks.
   
2. **Cross-Site Scripting (XSS)**:
   - Attempts to inject JavaScript payloads to see if the application improperly renders user input, potentially allowing XSS attacks.
   
3. **Directory Traversal**:
   - Injects directory traversal payloads to test if files outside the web root are accessible through URL parameters.

Each detected vulnerability is logged with details, including the affected URL, the payload used, and remediation suggestions.

---

## Important Note
This tool is designed as a simple vulnerability scanner. It **cannot detect all URLs** on every page because it only extracts links from `href` attributes in HTML. Some URLs, especially those generated dynamically by JavaScript, are not accessible to this scanner. 

> **If your application has URLs that are dynamically loaded by JavaScript, please add them manually to the scan target when running the script.**

Adding these URLs manually will ensure that the scanner tests all necessary parts of the application for potential vulnerabilities.

---

## Sample Usage

1. **Basic Scan**:
   ```bash
   python security_scanner.py -u "http://localhost:3000"
   ```

2. **Ignoring Specific Links**:
   ```bash
   python security_scanner.py -u "http://localhost:3000" -i "http://localhost:3000/ignore-this-link"
   ```

3. **Scan with Login**:
   ```bash
   python security_scanner.py -u "http://localhost:3000" -l "http://localhost:3000/login" -n "admin" -p "password"
   ```

---

## Sample Output
Upon completion, the tool generates a `report.json` file with details of any vulnerabilities found. A sample entry may look like:

```json
[
    {
        "timestamp": "2024-11-14T12:34:56.789",
        "type": "XSS",
        "url": "http://localhost:3000/vulnerable_form",
        "payload": "<script>alert('XSS')</script>",
        "form": "<form action='/submit' method='post'>...</form>",
        "remediation": "Sanitize and encode user input. Use Content Security Policy (CSP) headers."
    }
]
```

---

## Future Improvements
- **JavaScript URL Detection**: Expanding the scanner to detect URLs embedded in JavaScript would allow more thorough scanning.
- **Additional Vulnerabilities**: Adding modules for more complex vulnerabilities, such as CSRF and file upload vulnerabilities, would make this tool more comprehensive.

---
