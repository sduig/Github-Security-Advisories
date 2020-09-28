#/usr/bin/python3

import atoma
import requests

import atoma, requests
response = requests.get('https://github.com/security-advisories')
feed = atoma.parse_atom_bytes(response.content)

for post in feed.entries:
    print (post.id_)
    print (post.published)
    print (post.updated)
    print (post.title.value)
