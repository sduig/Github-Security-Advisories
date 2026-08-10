# Github-Security-Advisories
Python3 scripts created to extract Github Security Advisories from:
https://github.com/security-advisories

Stage 1

gsa_basic.py prints out base entries from the Github Security Advisories Atoma feed

gsa_advanced.py extracts key Atoma elements such as ID, Title, Updated, Published, CVE and stores the results in a CSV file.

gsa_advanced_proxy.py supports proxy requests and extracts key Atoma elements such as ID, Title, Updated, Published, CVE and stores the results in a CSV file.

gsa_advanced_parsed.py extracts key Atoma elements such as ID, Title, Updated, Published, CVE and parses any special characters ('[],') and stores the results in a CSV file.

gsa_advanced_proxy_parsed.py supports proxy requests, extracts key Atoma elements such as ID, Title, Updated, Published, CVE and parses any special characters ('[],') and stores the results in a CSV file.

Stage 2

The goal is to create a MISP CSV import feed by hosting the CSV file as an accessible web feed on a local server.

Make the downloaded feed accessible as a CSV or HTML file.

Edit MISP Feed

Enabled
Caching Enabled
Lookup Visible

Name
GSA CVEs

Provider
Cyber

Input Source
Network

URL
http://misp.user.com/GSA.html

Source Format
Freetext Parsed Feed

Creator organisation
Threat Intelligence

Target Event
Fixed Event

# Github-Security-Advisories Lambda Function
Deployment Instructions

1. Create IAM Role
json

Copy
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
Attach Managed Policy:

AmazonS3FullAccess (or custom policy with specific bucket permissions)
CloudWatchLogsFullAccess
2. Set Environment Variables
In Lambda Console → Configuration → Environment Variables:

FEED_URL=https://github.com/security-advisories
S3_BUCKET=your-lambda-output-bucket
S3_PREFIX=github-security-advisories/
3. Create Deployment Package
bash

Copy
# Create zip with dependencies
mkdir lambda_package
cp script.py lambda_package/

# Install dependencies in zip
cd lambda_package
pip install atoma requests pandas boto3 -t .
zip -r9 ../lambda_function.zip .

# Upload to Lambda
aws lambda update-function-code --function-name your-lambda-name --zip-file fileb://lambda_function.zip
4. Configure Event Bridge (Cron Trigger)
bash

Copy
# Run every 6 hours
aws events put-rule --name github-security-scan --schedule-expression "rate(6 hours)"

aws events put-targets --rule github-security-scan --targets "Id"="1","Arn"="arn:aws:lambda:region:account-id:function:your-lambda-name"
5. Required Python Dependencies
Ensure these are included in your deployment package:

atoma==0.1.19
requests==2.31.0
pandas==2.0.3
boto3==1.34.0
Security Enhancements
No hardcoded credentials - Uses IAM roles
S3 encryption - Enable server-side encryption on bucket
VPC configuration - Add VPC if accessing internal resources
Timeout settings - Set to 300 seconds (max)
Memory allocation - Start with 512MB, adjust based on usage
Expected Output
The Lambda function will:

✅ Fetch GitHub security advisories feed
✅ Parse and extract CVE data
✅ Clean and format data
✅ Save CSV and HTML to S3
✅ Log all operations to CloudWatch
✅ Return success/error status
