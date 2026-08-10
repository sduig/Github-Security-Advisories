import json
import os
import logging
import boto3
import atoma
import requests
import re
import pandas as pd
from io import BytesIO
from typing import List, Dict, Any
from datetime import datetime

# Configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment variables (set in Lambda console)
FEED_URL = os.environ.get('FEED_URL', 'https://github.com/security-advisories')
S3_BUCKET = os.environ.get('S3_BUCKET', 'your-lambda-output-bucket')
S3_PREFIX = os.environ.get('S3_PREFIX', 'github-security-advisories/')
CSV_FILENAME = 'GithubSA.csv'
HTML_FILENAME = 'GithubSA.html'

# Initialize S3 client
s3_client = boto3.client('s3')

def extract_cve(content: str) -> List[str]:
    """Extract all CVE IDs from content."""
    if not content:
        return []
    return re.findall(r"CVE-\d{4}-\d{4,7}", content)

def extract_id_and_title(title: str) -> tuple:
    """Extract ID and clean title from formatted string."""
    if not title:
        return "", ""
    
    id_match = re.search(r"\[(.*?)\]", title)
    vuln_id = id_match.group(1) if id_match else ""
    
    # Remove ID part and clean title
    clean_title = re.sub(r"\s.*", "", title).strip()
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
            # Handle None values safely
            title_value = getattr(vuln, 'title', None)
            content_value = getattr(vuln, 'content', None)
            published = getattr(vuln, 'published', None)
            updated = getattr(vuln, 'updated', None)
            
            if not title_value:
                continue
                
            vuln_id, clean_title = extract_id_and_title(
                getattr(title_value, 'value', '')
            )
            
            cves = extract_cve(getattr(content_value, 'value', '') if content_value else '')
            published = published.strftime('%Y/%m/%d') if published else ""
            updated = updated.strftime('%Y/%m/%d') if updated else ""

            new_items.append({
                "ID": vuln_id,
                "PUBLISHED": published,
                "UPDATED": updated,
                "TITLE": clean_title,
                "CATEGORY": "",  # Placeholder if not available
                "CVE": ", ".join(cves) if cves else ""
            })
        except Exception as e:
            logger.warning(f"Skipping malformed entry: {e}")
            continue

    return pd.DataFrame(new_items, columns=["ID", "PUBLISHED", "UPDATED", "TITLE", "CATEGORY", "CVE"])

def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Clean and standardize DataFrame columns."""
    if df.empty:
        return df
        
    # Strip whitespace and remove special characters
    for col in df.columns:
        df[col] = df[col].astype(str).str.strip().str.replace(r"[\[\]']", "", regex=True)
    return df

def save_to_s3(df: pd.DataFrame, filename: str, content_type: str = 'text/csv'):
    """Save DataFrame to S3 bucket."""
    try:
        # Convert DataFrame to string
        if content_type == 'text/html':
            csv_content = df.to_html(index=False)
        else:
            csv_content = df.to_csv(index=False)
        
        # Generate timestamped key
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        s3_key = f"{S3_PREFIX}{filename}"
        
        # Upload to S3
        s3_client.put_object(
            Bucket=S3_BUCKET,
            Key=s3_key,
            Body=csv_content.encode('utf-8'),
            ContentType=content_type,
            Metadata={
                'generated-at': timestamp,
                'record-count': str(len(df))
            }
        )
        
        logger.info(f"Successfully saved {filename} to s3://{S3_BUCKET}/{s3_key}")
        return f"s3://{S3_BUCKET}/{s3_key}"
        
    except Exception as e:
        logger.error(f"Failed to save to S3: {e}")
        raise

def lambda_handler(event, context):
    """Main Lambda handler."""
    logger.info(f"Starting script execution. Request ID: {context.aws_request_id}")
    
    try:
        # Fetch and parse feed
        entries = fetch_and_parse_feed(FEED_URL)
        if not entries:
            logger.warning("No entries found in feed.")
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'No entries found',
                    'entries_count': 0
                })
            }

        # Process and clean data
        df = process_entries(entries)
        df = clean_dataframe(df)
        
        if df.empty:
            logger.warning("DataFrame is empty after processing.")
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'No valid entries after processing',
                    'entries_count': 0
                })
            }

        # Save to S3
        csv_url = save_to_s3(df, CSV_FILENAME, 'text/csv')
        html_url = save_to_s3(df, HTML_FILENAME, 'text/html')
        
        logger.info(f"Processed {len(df)} entries")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Successfully processed security advisories',
                'entries_count': len(df),
                'csv_url': csv_url,
                'html_url': html_url
            })
        }
        
    except Exception as e:
        logger.error(f"Error in lambda execution: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Script execution failed',
                'error': str(e)
            })
        }
