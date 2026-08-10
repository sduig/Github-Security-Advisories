#!/usr/bin/env python3

import atoma
import requests
import re
import pandas as pd
import logging
from pathlib import Path
from typing import List, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Constants
FEED_URL = "https://github.com/security-advisories"
OUTPUT_DIR = Path("/var/www/gsa")
CSV_FILE = OUTPUT_DIR / "GithubSA.csv"
HTML_FILE = OUTPUT_DIR / "GithubSA.html"

def extract_cve(content: str) -> List[str]:
    """Extract all CVE IDs from content."""
    return re.findall(r"CVE-\d{4}-\d{4,7}", content)

def extract_id_and_title(title: str) -> tuple:
    """Extract ID and clean title from formatted string."""
    id_match = re.search(r"\[(.*?)\]", title)
    clean_title = re.sub(r"\s.*", "", title).strip()
    vuln_id = id_match.group(1) if id_match else ""
    return vuln_id, clean_title

def fetch_and_parse_feed(url: str) -> List[Dict[str, Any]]:
    """Fetch and parse Atom feed from GitHub."""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        feed = atoma.parse_atom_bytes(response.content)
        return feed.entries
    except requests.RequestException as e:
        logger.error(f"Failed to fetch feed: {e}")
        return []
    except Exception as e:
        logger.error(f"Error parsing feed: {e}")
        return []

def process_entries(entries) -> pd.DataFrame:
    """Process feed entries into a structured DataFrame."""
    new_items = []

    for vuln in entries:
        try:
            vuln_id, clean_title = extract_id_and_title(vuln.title.value)
            cves = extract_cve(vuln.content.value)
            published = vuln.published.strftime('%Y/%m/%d') if vuln.published else ""
            updated = vuln.updated.strftime('%Y/%m/%d') if vuln.updated else ""

            new_items.append({
                "ID": vuln_id,
                "PUBLISHED": published,
                "UPDATED": updated,
                "TITLE": clean_title,
                "CATEGORY": "",  # Placeholder if not available
                "CVE": ", ".join(cves)  # Join multiple CVEs
            })
        except AttributeError as e:
            logger.warning(f"Skipping malformed entry: {e}")
            continue

    return pd.DataFrame(new_items, columns=["ID", "PUBLISHED", "UPDATED", "TITLE", "CATEGORY", "CVE"])

def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Clean and standardize DataFrame columns."""
    # Strip whitespace and remove special characters
    for col in df.columns:
        df[col] = df[col].astype(str).str.strip().str.replace(r"[\[\]']", "", regex=True)
    return df

def save_to_csv(df: pd.DataFrame, filepath: Path):
    """Save DataFrame to CSV."""
    try:
        df.to_csv(filepath, index=False, encoding="utf-8")
        logger.info(f"CSV saved to {filepath}")
    except Exception as e:
        logger.error(f"Failed to save CSV: {e}")

def save_to_html(df: pd.DataFrame, filepath: Path):
    """Save DataFrame to HTML."""
    try:
        df.to_html(filepath, index=False)
        logger.info(f"HTML saved to {filepath}")
    except Exception as e:
        logger.error(f"Failed to save HTML: {e}")

def main():
    """Main execution function."""
    # Ensure output directory exists
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Fetch and parse feed
    entries = fetch_and_parse_feed(FEED_URL)
    if not entries:
        logger.warning("No entries found. Exiting.")
        return

    # Process and clean data
    df = process_entries(entries)
    df = clean_dataframe(df)

    # Save outputs
    save_to_csv(df, CSV_FILE)
    save_to_html(df, HTML_FILE)

if __name__ == "__main__":
    main()
