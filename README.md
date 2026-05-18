# Integrated Web Crawler in Security Scanner

## Project Title

**Improving Penetration Testing Efficiency and Coverage Through Web Crawler Integration in Security Scanners**

## Overview

This project is a web security scanning system that integrates a **web crawler** with a **vulnerability scanner** to improve testing coverage and reduce manual endpoint collection.

Traditional web vulnerability scanners usually depend on manually supplied URLs. This can cause hidden pages, linked routes, forms, and internal endpoints to be missed. This project solves that limitation by first crawling the target web application, collecting discovered URLs and forms, then passing them to the scanner for security testing.

The system helps penetration testers identify a wider attack surface before running vulnerability checks.

## Main Objective

The main objective of this project is to improve penetration testing efficiency and coverage by automatically discovering reachable web pages, forms, and endpoints before vulnerability scanning is performed.

## Problem Statement

Manual URL collection during penetration testing is time-consuming and incomplete. Testers may miss hidden pages, linked endpoints, and vulnerable forms if they only scan URLs they already know.

This project addresses the issue by integrating a crawler into the scanner workflow, allowing the system to automatically discover and scan more attack surfaces.

## Key Features

- Automatically crawls target web applications
- Discovers internal links and endpoints
- Extracts forms and input fields
- Stores discovered URLs for scanning
- Performs vulnerability checks on discovered targets
- Displays scan results through a web dashboard
- Reduces manual testing effort
- Improves vulnerability scanning coverage

## System Workflow

```text
Target URL
   ↓
Crawler visits the page
   ↓
Crawler extracts links, forms, inputs, and endpoints
   ↓
Discovered items are stored
   ↓
Crawler continues visiting unvisited pages
   ↓
Scanner tests discovered URLs and forms
   ↓
Results are displayed in the dashboard/report
```

## System Architecture

The system consists of three main components:

### 1. Web Crawler

The crawler is responsible for visiting the target web application and collecting reachable pages, links, forms, and input fields.

Example responsibilities:

- Visit the target URL
- Extract anchor links
- Detect forms and parameters
- Avoid duplicate URLs
- Continue crawling until all reachable pages are visited

### 2. Vulnerability Scanner

The scanner receives discovered URLs and forms from the crawler, then performs security checks.

Possible vulnerability checks include:

- SQL Injection testing
- Cross-Site Scripting testing
- Security header checks
- Form input testing
- Basic endpoint exposure checks

### 3. Web Dashboard

The dashboard provides a user interface for starting scans and viewing results.

Example dashboard functions:

- Enter target URL
- Start crawler and scanner
- View discovered endpoints
- View vulnerability findings
- Generate scan summary

## Technologies Used

- Python
- Flask
- Selenium
- BeautifulSoup
- Requests
- HTML
- CSS
- JavaScript

## Project Files

Example files used in this project:

```text
Crawlerer.py
CrawlerScanner.py
CrawlerScanner_one_v3_time.py
CrawlerScanner_one_v3_time_updated.py
templates/
  ├── home.html
  ├── index.html
  └── report.html
static/
  ├── css/
  └── js/
```

## Installation

### 1. Clone the Project

```bash
git clone <repository-url>
cd <project-folder>
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
```

### 3. Activate the Virtual Environment

For Windows:

```bash
venv\Scripts\activate
```

For Linux or macOS:

```bash
source venv/bin/activate
```

### 4. Install Requirements

```bash
pip install -r requirements.txt
```

If `requirements.txt` is not available, install the main dependencies manually:

```bash
pip install flask selenium beautifulsoup4 requests
```

### 5. Install Browser Driver

If the crawler uses Selenium, make sure the correct browser driver is installed.

For Chrome:

- Install Google Chrome
- Install ChromeDriver matching your Chrome version
- Add ChromeDriver to your system PATH

## Usage

### 1. Run the Flask Application

```bash
python CrawlerScanner.py
```

or:

```bash
python CrawlerScanner_one_v3_time.py
```

### 2. Open the Dashboard

Open your browser and go to:

```text
http://127.0.0.1:5000
```

### 3. Start a Scan

1. Enter the target URL.
2. Start the crawler.
3. Wait for the crawler to discover pages and forms.
4. Run vulnerability scanning on the discovered endpoints.
5. Review the results in the dashboard.

## Example Target

For testing purposes, use intentionally vulnerable applications only, such as:

- OWASP Juice Shop
- DVWA
- bWAPP
- WebGoat

Do not scan websites that you do not own or do not have permission to test.

## Example Output

The scanner may produce results such as:

```text
Discovered URLs:
- http://localhost:3000/
- http://localhost:3000/login
- http://localhost:3000/search
- http://localhost:3000/contact

Discovered Forms:
- Login form
- Search form
- Contact form

Potential Vulnerabilities:
- Missing security headers
- Reflected input detected
- Possible SQL Injection parameter
- Possible Cross-Site Scripting input
```

## Expected Benefits

This project improves penetration testing by:

- Increasing web application coverage
- Reducing manual URL collection
- Discovering hidden or forgotten endpoints
- Improving scanner accuracy through better input discovery
- Supporting a more complete vulnerability assessment workflow

## Project Contribution

The main contribution of this project is the integration of an automated web crawler into a security scanner. This allows the scanner to discover and test more web application endpoints compared to a scanner that only uses manually entered URLs.

This improves both testing efficiency and attack surface coverage.

## Limitations

Current limitations may include:

- Dynamic JavaScript-heavy websites may require additional crawler tuning
- Authentication-protected pages may need login/session support
- Some vulnerabilities may require deeper manual verification
- The scanner may produce false positives
- Crawling depth may need to be controlled to avoid long scan times

## Future Enhancements

Possible future improvements:

- Add authenticated crawling
- Add sitemap generation
- Add PDF report export
- Add severity scoring
- Add scan history
- Add more vulnerability test modules
- Add support for API endpoint discovery
- Add crawler depth and scope control
- Improve JavaScript rendering support

## Ethical Use

This tool is intended for educational, research, and authorized penetration testing purposes only.

Only use this scanner on:

- Your own web applications
- Lab environments
- CTF platforms
- Systems where you have written permission to test

Unauthorized scanning may be illegal.

## Suggested Project Defense Explanation

> This project improves penetration testing efficiency by integrating a web crawler with a vulnerability scanner. The crawler automatically discovers reachable pages, forms, and endpoints from the target website. These discovered attack surfaces are then passed to the scanner for vulnerability testing. As a result, the scanner can test more areas of the web application compared to traditional scanning methods that rely only on manually provided URLs.

## Author

**Asyraf**

Final Year Project  
Cybersecurity / Information Technology
