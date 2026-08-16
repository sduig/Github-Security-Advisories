import requests
import json
import os
from datetime import datetime

# Configuration
# 1. Set your GitHub Personal Access Token (PAT)
# You can generate one at: https://github.com/settings/tokens
# Required scopes: 'public_repo' (for public advisories) or 'read:org'
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "YOUR_GITHUB_TOKEN_HERE") 

# 2. The Endpoint
# We use the GraphQL API endpoint, not the HTML page
FEED_URL = "https://api.github.com/graphql"

# 3. GraphQL Query
# This query fetches the latest security advisories
QUERY = """
query {
  securityVulnerabilities(first: 20, orderBy: {field: UPDATED_AT, direction: DESC}) {
    nodes {
      package {
        name
        ecosystem
      }
      vulnerabilityId
      severity
      description
      publishedAt
      updatedAt
      references {
        url
      }
      cwes {
        cweId
        name
      }
    }
  }
}
"""

def fetch_advisories():
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Content-Type": "application/json"
    }

    try:
        print(f"🔐 Authenticating with GitHub API...")
        response = requests.post(FEED_URL, json={"query": QUERY}, headers=headers, timeout=30)

        if response.status_code == 200:
            data = response.json()
            
            if "errors" in data:
                print(f"❌ API Error: {data['errors']}")
                return
            
            vulnerabilities = data["data"]["securityVulnerabilities"]["nodes"]
            
            if not vulnerabilities:
                print("⚠️ No vulnerabilities found or API returned empty data.")
                return

            print(f"✅ Successfully fetched {len(vulnerabilities)} advisories.\n")

            # Process and Print Data
            print(f"{'ID':<25} {'Package':<20} {'Severity':<10} {'Published':<20} {'Description (Truncated)'}")
            print("-" * 100)

            for vuln in vulnerabilities:
                pkg_name = vuln['package']['name']
                pkg_eco = vuln['package']['ecosystem']
                vuln_id = vuln['vulnerabilityId']
                severity = vuln['severity']
                published = vuln['publishedAt']
                desc = (vuln['description'][:50] + "...") if len(vuln['description']) > 50 else vuln['description']
                
                print(f"{vuln_id:<25} {pkg_name:<20} ({pkg_eco}) {severity:<10} {published:<20} {desc}")

            # Optional: Save to JSON file
            save_to_json(data)

        else:
            print(f"❌ Failed to fetch data. Status Code: {response.status_code}")
            print(f"Response: {response.text}")

    except Exception as e:
        print(f"❌ An error occurred: {e}")

def save_to_json(data):
    filename = f"advisories_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"\n💾 Data saved to: {filename}")
    except Exception as e:
        print(f"❌ Error saving file: {e}")

if __name__ == "__main__":
    # Check if token is set
    if GITHUB_TOKEN == "YOUR_GITHUB_TOKEN_HERE" and not os.getenv("GITHUB_TOKEN"):
        print("⚠️  WARNING: No valid GitHub Token found.")
        print("Please set the GITHUB_TOKEN environment variable or edit the script.")
        print("Example: export GITHUB_TOKEN=ghp_your_token_here")
    else:
        fetch_advisories()
