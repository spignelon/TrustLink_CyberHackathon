from flask import Flask, request, jsonify
from transformers import pipeline
import os
import urllib.request
import json

app = Flask(__name__)

# Load the text classification pipeline
pipe = pipeline("text-classification", model="DunnBC22/codebert-base-Malicious_URLs", top_k=None)

def download_if_missing(file_url, file_path):
    if not os.path.exists(file_path):
        try:
            print(f"File '{file_path}' not found. Downloading from '{file_url}'...")
            urllib.request.urlretrieve(file_url, file_path)
            print(f"Download complete: '{file_path}'")
            return True
        except Exception as e:
            print(f"Error downloading file: {e}")
            return False
    else:
        print(f"File '{file_path}' already exists.")
        return False

file_urls = ["https://urlhaus.abuse.ch/downloads/json_online/", "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Dead/hosts", "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts", "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt", "https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.txt", "https://raw.githubusercontent.com/elliotwutingfeng/GlobalAntiScamOrg-blocklist/main/global-anti-scam-org-scam-urls-pihole.txt", "https://blocklistproject.github.io/Lists/alt-version/fraud-nl.txt", "https://rescure.me/rescure_domain_blacklist.txt", "https://raw.githubusercontent.com/HexxiumCreations/threat-list/gh-pages/hosts.txt", "https://rescure.me/rescure_domain_blacklist.txt", "https://www.usom.gov.tr/url-list.txt", "https://openphish.com/feed.txt", ]
titles = ["urlhaus abuse.ch", "Dead domain", "Risk hosts", ]

def extract_domains_from_hosts(filepath):
  with open(filepath, 'r') as f:
    # Skip empty lines and comments (lines starting with #)
    lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    # Extract domains
    domains = [line.split()[1].lstrip('www.') for line in lines]
    # Print unique domains
    return domains

def extract_domain(url):
  try:
    if url[:7] != "http://" and url[:8] != "https://" and url[:4] != "www.":
      return url
    # Parse the URL
    if url[:4] == "www.":
        domain = url[4:]
        return domain
    parsed_url = urllib.parse.urlparse(url)
    # Get the netloc (domain name and subdomain)
    netloc = parsed_url.netloc
    # Remove port number if present
    if ':' in netloc:
      netloc = netloc.split(':')[0]
    # Return the domain name
    domain = netloc.lower()
    return domain
  except Exception as e:
    print(f"Error extracting domain: {e}")
    return None

# downloading all host lists
for i in range(len(file_urls)):
    print(download_if_missing(file_urls[i], f'data/{i}.txt'))

with open('data/0.txt', 'r') as f:
    data = json.load(f)

extracted_data = []
for key, value in data.items():
    for item in value:
        extracted_data.append({
            "url": item["url"],
            "threat": item["threat"]
            })

# extracting domains from host files
domains1 = extract_domains_from_hosts("data/1.txt")
domains2 = extract_domains_from_hosts("data/2.txt")

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Get the JSON data from the request
        data = request.get_json()

        # Extract the URL from the JSON data
        url = data['url']
        
        # urlhaus abuse.ch
        for i in range(len(extracted_data)):
            if extracted_data[i]['url'] == url:
                return jsonify({"label": extracted_data[i]['threat'], "score":1})
        
        print(domains1)
        print(extract_domain(url))
        
        # Dead domain
        for i in domains1:
            if i == extract_domain(url):
                return jsonify({"label": "Dead Host", "score": 1}) 
            
        # malware risk hosts
        for i in domains2:
            if i == extract_domain(url):
                return jsonify({"label": "malware", "score": 1})
        
        # huggingface ml
        result = pipe(url)  

        # Return the prediction as JSON
        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True)
