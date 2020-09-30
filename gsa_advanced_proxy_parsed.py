#/usr/bin/python3

import atoma
import requests
import re
import pandas as pd

#Proxy support
proxies = {
      "http"="http://<<proxy>>:80"
      "https"="https://<<proxy>>:80"
      }

response = requests.get('https://github.com/security-advisories', proxies=proxies)
feed = atoma.parse_atom_bytes(response.content)

new_items = []

#Collect all Vulnerabilities with a CVE
for vuln in feed.entries:
    new_item = {}
    new_item['Id'] = re.findall(r'\[(.*?)\]', vuln.title.value)
    new_item['Published'] = vuln.published.strftime('%Y/%m/%d')
    new_item['Updated'] = vuln.updated.strftime('%Y/%m/%d')
    new_item['Title'] = re.findall(r'\s.*',vuln.title.value)
    new_item['Cve'] = re.findall(r'CVE-\d{4}-\d{4,7}',vuln.content.value)
    new_items.append(new_item)
    print (new_items)

df = pd.DataFrame(new_items,columns=['Id','Published','Updated','Title','Category','Cve'])

#Convert dtype to str
df["Id"]= df["Id"].astype(str)
df["Published"]= df["Published"].astype(str)
df["Updated"]= df["Updated"].astype(str)
df["Title"]= df["Title"].astype(str)
df["Category"]= df["Category"].astype(str)
df["Cve"]= df["Cve"].astype(str)

#Replace special characters
df1 = pd.DataFrame(columns=['ID','PUBLISHED','UPDATED','TITLE','CATEGORY','CVE'])
df1['ID']  = df['Id'].str.replace("\[|\]|\'", "")
df1['PUBLISHED']  = df['Published'].str.replace("\[|\]|\'", "")
df1['UPDATED']  = df['Updated'].str.replace("\[|\]|\'", "")
df1['TITLE']  = df['Title'].str.replace("\[|\]|\'", "")
df1['CATEGORY']  = df['Category'].str.replace("\[|\]|\'", "")
df1['CVE']  = df['Cve'].str.replace("\[|\]|\'", "")
df1.head()

#Export to CSV file
df1.to_csv('/home/<<user>>/GithubSA.csv',index=False, encoding = 'utf-8')
