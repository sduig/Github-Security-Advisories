#/usr/bin/python3

import atoma
import requests
import re
import pandas as pd

response = requests.get('https://github.com/security-advisories')
feed = atoma.parse_atom_bytes(response.content)

new_items = []

for vuln in feed.entries:
    new_item = {}
    new_item['Id'] = re.findall(r'\[(.*?)\]', vuln.title.value)
    new_item['Published'] = vuln.published.strftime('%Y/%m/%d')
    new_item['Updated'] = vuln.updated.strftime('%Y/%m/%d')
    new_item['Title'] = re.findall(r'\s.*',vuln.title.value)
    new_item['CVE'] = re.findall(r'CVE-\d{4}-\d{4,7}',vuln.content.value)
    new_items.append(new_item)
    print (new_items)

df = pd.DataFrame(new_items,columns=['Id','Published','Updated','Title','Category','CVE'])
df.head()
df.to_csv('/home/<<user>>/GithubSA.csv',index=False, encoding = 'utf-8')
