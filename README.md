# Github-Security-Advisories
Python3 scripts created to extract Github Security Advisories from:
https://github.com/security-advisories

gsa_basic.py prints out base entries from the Github Security Advisories Atoma feed

gsa_advanced.py extracts key Atoma elements such as ID, Title, Updated, Published, CVE and stores the results in a CSV file.

gsa_advanced_proxy.py supports proxy requests and extracts key Atoma elements such as ID, Title, Updated, Published, CVE and stores the results in a CSV file.

gsa_advanced_parsed.py extracts key Atoma elements such as ID, Title, Updated, Published, CVE and parses any special characters ('[],') and stores the results in a CSV file.

gsa_advanced_proxy_parsed.py supports proxy requests, extracts key Atoma elements such as ID, Title, Updated, Published, CVE and parses any special characters ('[],') and stores the results in a CSV file.

The goal is to create a MISP CSV import feed by hosting the CSV file as an accessible web feed on a local server.
