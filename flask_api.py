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
titles = ["urlhaus abuse.ch", "Dead domain", "Risk hosts", "Anti malware list", "List of Malware Domains", "List scam urls by https://www.globalantiscam.org/", "List fraud urls by the The Block List Project", "Cyber Threat Intelligence Feed https://rescure.me/", "Community driven malicious domains list by Hexxium Creations", "", "Computer Emergency Response Team of the Republic of Turkey", "Openphish phishing intelligence list"]

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

def extract_domains_from_hosts3(hosts_file_path):
    # Initialize an empty list to store the domains
    domains_list = []

    # Read the hosts file and extract domains
    with open(hosts_file_path, 'r') as file:
        for line in file:
            # Ignore comments and blank lines
            if not line.startswith('#') and not line.startswith('!') and line.strip():
                # Split the line into parts
                parts = line.split()
                
                # Check if there are at least 2 parts in the line
                if len(parts) >= 2:
                    # Extract domain from the second part
                    domain = parts[1]
                    domains_list.append(domain)

    return domains_list

# read domains from file and create a list
def read_domains_from_file(file_path):
    with open(file_path, 'r') as file:
        domains_list = [line.strip() for line in file if not line.startswith(('#', '!'))]
    return domains_list

# extracting domains from host files into memory
domains1 = extract_domains_from_hosts("data/1.txt")
domains2 = extract_domains_from_hosts("data/2.txt")
domains3 = extract_domains_from_hosts3("data/3.txt")
domains4 = read_domains_from_file("data/4.txt")
domains5 = read_domains_from_file("data/5.txt")
domains6 = read_domains_from_file("data/6.txt")
domains7 = read_domains_from_file("data/7.txt")
domains8 = extract_domains_from_hosts3("data/8.txt")
domains10 = read_domains_from_file("data/10.txt")
domains11 = read_domains_from_file("data/11.txt")

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
        
        print(extract_domain(url))
        
        # Dead domain
        for i in domains1:
            if i == extract_domain(url):
                return jsonify({"label": "Dead Host", "score": 1}) 
            
        # malware risk hosts
        for i in domains2:
            if i == extract_domain(url):
                return jsonify({"label": "malware", "score": 1})
        
        # risk hosts 3
        for i in domains3:
            if i == extract_domain(url):
                return jsonify({"label": "malware", "score": 1})
        
        # List of Malware Domains 4
        for i in domains4:
            if i == extract_domain(url):
                return jsonify({"label": "malware", "score": 1})
        
        # List scam urls https://www.globalantiscam.org/
        for i in domains5:
            if i == extract_domain(url):
                return jsonify({"label": "scam", "score": 1})
        
        # List fraud urls by the The Block List Project
        for i in domains6:
            if i == extract_domain(url):
                return jsonify({"label": "fraud", "score": 1})
        
        # Cyber Threat Intelligence Feed https://rescure.me/
        for i in domains7:
            if i == extract_domain(url):
                return jsonify({"label": "malware", "score": 1})
        
        # Community driven malicious domains list by Hexxium Creations
        for i in domains8:
            if i == extract_domain(url):
                return jsonify({"label": "malware", "score": 1})
        
        # Computer Emergency Response Team of the Republic of Turkey
        for i in domains10:
            if i == extract_domain(url):
                return jsonify({"label": "malicious", "score": 1})
        
        # Openphish phishing intelligence list
        for i in domains11:
            if i == url:
                return jsonify({"label": "phishing", "score": 1})
        
        # huggingface ml
        result = pipe(url)  

        # Return the prediction as JSON
        return jsonify(result[0])

    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True)
